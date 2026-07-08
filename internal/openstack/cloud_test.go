package openstack_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/azimuth-cloud/cluster-api-janitor-openstack/internal/openstack"
)

// keystoneServer is a configurable mock Keystone server for unit tests.
type keystoneServer struct {
	*httptest.Server
	tokenStatus   int
	tokenUserID   string
	catalogStatus int
	catalog       map[string]any
}

func newKeystoneServer(t *testing.T) *keystoneServer {
	t.Helper()
	ks := &keystoneServer{
		tokenStatus:   http.StatusCreated,
		tokenUserID:   "test-user-id",
		catalogStatus: http.StatusOK,
		catalog:       map[string]any{"catalog": []any{}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if ks.tokenStatus >= 400 {
			w.WriteHeader(ks.tokenStatus)
			return
		}
		w.Header().Set("X-Subject-Token", "test-token-abc123")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ks.tokenStatus)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": map[string]any{
				"user": map[string]any{"id": ks.tokenUserID},
			},
		})
	})
	mux.HandleFunc("/v3/auth/catalog", func(w http.ResponseWriter, r *http.Request) {
		if ks.catalogStatus == http.StatusNotFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ks.catalogStatus)
		_ = json.NewEncoder(w).Encode(ks.catalog)
	})
	ks.Server = httptest.NewServer(mux)
	t.Cleanup(ks.Close)
	return ks
}

// newTLSKeystoneServer creates a TLS-enabled mock Keystone server.
func newTLSKeystoneServer(t *testing.T) *keystoneServer {
	t.Helper()
	ks := &keystoneServer{
		tokenStatus:   http.StatusCreated,
		tokenUserID:   "test-user-id",
		catalogStatus: http.StatusOK,
		catalog:       map[string]any{"catalog": []any{}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Subject-Token", "test-token-tls")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": map[string]any{
				"user": map[string]any{"id": ks.tokenUserID},
			},
		})
	})
	mux.HandleFunc("/v3/auth/catalog", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(ks.catalog)
	})
	ks.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ks.Close)
	return ks
}

func buildCloudsYAML(authURL, authType string) string {
	return fmt.Sprintf(`
clouds:
  openstack:
    auth_type: %s
    auth:
      auth_url: %s
      application_credential_id: appcred-abc123
      application_credential_secret: super-secret
    region_name: RegionOne
    interface: public
`, authType, authURL)
}

func buildCloudsYAMLWithInterface(authURL, iface string) string {
	return fmt.Sprintf(`
clouds:
  openstack:
    auth_type: v3applicationcredential
    auth:
      auth_url: %s
      application_credential_id: appcred-abc123
      application_credential_secret: super-secret
    interface: %s
`, authURL, iface)
}

func buildCloudsYAMLWithRegion(authURL, region string) string {
	if region == "" {
		return fmt.Sprintf(`
clouds:
  openstack:
    auth_type: v3applicationcredential
    auth:
      auth_url: %s
      application_credential_id: appcred-abc123
      application_credential_secret: super-secret
    interface: public
`, authURL)
	}
	return fmt.Sprintf(`
clouds:
  openstack:
    auth_type: v3applicationcredential
    auth:
      auth_url: %s
      application_credential_id: appcred-abc123
      application_credential_secret: super-secret
    region_name: %s
    interface: public
`, authURL, region)
}

// catalogWith builds a catalog payload with one service and given endpoints.
func catalogWith(entries ...map[string]any) map[string]any {
	return map[string]any{"catalog": entries}
}

func serviceEntry(svcType string, endpoints ...map[string]any) map[string]any {
	return map[string]any{
		"type":      svcType,
		"endpoints": endpoints,
	}
}

func endpoint(iface, regionID, url string) map[string]any {
	return map[string]any{
		"interface": iface,
		"region_id": regionID,
		"url":       url,
	}
}

// ── US1.1: Authentication via Application Credential v3 ────────────────────

// Scenario: Successful authentication
// Given a clouds.yaml with auth_type "v3applicationcredential"
// And a valid application_credential_id and application_credential_secret
// When the operator initialises the OpenStack connection
// Then an X-Auth-Token is obtained from Keystone
// And the service catalog is loaded
func TestAuthenticate_SuccessfulAuthentication(t *testing.T) {
	ks := newKeystoneServer(t)
	ks.catalog = catalogWith(
		serviceEntry("compute",
			endpoint("public", "RegionOne", "http://compute.example.com"),
		),
	)

	clouds := buildCloudsYAML(ks.URL, "v3applicationcredential")
	session, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !session.IsAuthenticated() {
		t.Error("expected session to be authenticated")
	}
	if session.UserID() != "test-user-id" {
		t.Errorf("expected userID %q, got %q", "test-user-id", session.UserID())
	}
}

// Scenario: Authentication with unsupported type
// Given a clouds.yaml with auth_type "password"
// When the operator attempts to create a Cloud client
// Then an UnsupportedAuthTypeError is raised
func TestAuthenticate_UnsupportedAuthType(t *testing.T) {
	ks := newKeystoneServer(t)
	clouds := buildCloudsYAML(ks.URL, "password")

	_, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")

	if err == nil {
		t.Fatal("expected UnsupportedAuthTypeError, got nil")
	}
	var target *openstack.UnsupportedAuthTypeError
	if !errorAs(err, &target) {
		t.Fatalf("expected *UnsupportedAuthTypeError, got %T: %v", err, err)
	}
	if target.AuthType != "password" {
		t.Errorf("expected AuthType %q, got %q", "password", target.AuthType)
	}
}

// Scenario: Cloud missing in clouds.yaml
func TestAuthenticate_CloudNotFound(t *testing.T) {
	ks := newKeystoneServer(t)
	clouds := buildCloudsYAML(ks.URL, "v3applicationcredential")

	_, err := openstack.Authenticate(context.Background(), clouds, "nonexistent-cloud", "")

	if err == nil {
		t.Fatal("expected error for missing cloud, got nil")
	}
}

// Scenario: Invalid clouds.yaml (malformed YAML)
func TestAuthenticate_InvalidCloudsYAML(t *testing.T) {
	_, err := openstack.Authenticate(context.Background(), "not: valid: yaml: :", "openstack", "")

	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

// ── US1.3: Revoked or invalid credential handling ───────────────────────────

// Scenario: Application credential deleted before purge (token request → 404)
// Given a cluster being deleted
// And the application credential has already been deleted
// When the operator attempts to authenticate
// Then is_authenticated returns false
// And no fatal error is raised
func TestAuthenticate_DeletedApplicationCredential_Returns404(t *testing.T) {
	ks := newKeystoneServer(t)
	ks.tokenStatus = http.StatusNotFound

	clouds := buildCloudsYAML(ks.URL, "v3applicationcredential")
	session, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")

	if err != nil {
		t.Fatalf("expected no error for deleted appcred (404), got: %v", err)
	}
	if session.IsAuthenticated() {
		t.Error("expected session to be unauthenticated when appcred is deleted")
	}
}

// Scenario: Token request fails with a non-404 error
// When the operator attempts to authenticate
// Then the error is propagated
func TestAuthenticate_TokenRequestFails_NonFatal(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		code := code
		t.Run(fmt.Sprintf("HTTP_%d", code), func(t *testing.T) {
			ks := newKeystoneServer(t)
			ks.tokenStatus = code

			clouds := buildCloudsYAML(ks.URL, "v3applicationcredential")
			_, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")

			if err == nil {
				t.Fatalf("expected error for HTTP %d, got nil", code)
			}
		})
	}
}

// Scenario: Catalog returns 404
// Given a valid Keystone URL but the catalog returns 404
// When the operator loads the catalog
// Then is_authenticated returns false
// And no fatal error is raised
func TestAuthenticate_CatalogReturns404(t *testing.T) {
	ks := newKeystoneServer(t)
	ks.catalogStatus = http.StatusNotFound

	clouds := buildCloudsYAML(ks.URL, "v3applicationcredential")
	session, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")

	if err != nil {
		t.Fatalf("expected no error when catalog returns 404, got: %v", err)
	}
	if session.IsAuthenticated() {
		t.Error("expected session to be unauthenticated when catalog returns 404")
	}
}

// ── US1.2: Catalog filtering by interface and region ────────────────────────

// Scenario: Endpoint selected by configured interface
// Given a catalog with "public" and "internal" endpoints
// And the configured interface is "public"
// When the catalog is loaded
// Then only "public" endpoints are retained
func TestAuthenticate_FiltersByInterface_Public(t *testing.T) {
	ks := newKeystoneServer(t)
	ks.catalog = catalogWith(
		serviceEntry("compute",
			endpoint("public", "RegionOne", "http://compute-public.example.com"),
			endpoint("internal", "RegionOne", "http://compute-internal.example.com"),
		),
		serviceEntry("network",
			endpoint("internal", "RegionOne", "http://network-internal.example.com"),
		),
	)

	clouds := buildCloudsYAMLWithInterface(ks.URL, "public")
	session, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !session.IsAuthenticated() {
		t.Fatal("expected session to be authenticated")
	}
	// compute endpoint should exist (public)
	if !session.HasEndpoint("compute") {
		t.Error("expected compute endpoint to be present")
	}
	// network endpoint should NOT exist (only internal)
	if session.HasEndpoint("network") {
		t.Error("expected network endpoint to be absent (only internal available)")
	}
}

// Scenario: Endpoint selected by configured interface (internal)
func TestAuthenticate_FiltersByInterface_Internal(t *testing.T) {
	ks := newKeystoneServer(t)
	ks.catalog = catalogWith(
		serviceEntry("compute",
			endpoint("public", "RegionOne", "http://compute-public.example.com"),
		),
		serviceEntry("network",
			endpoint("internal", "RegionOne", "http://network-internal.example.com"),
		),
	)

	clouds := buildCloudsYAMLWithInterface(ks.URL, "internal")
	session, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session.HasEndpoint("compute") {
		t.Error("expected compute endpoint to be absent (only public available)")
	}
	if !session.HasEndpoint("network") {
		t.Error("expected network endpoint to be present (internal)")
	}
}

// Scenario: Endpoint selected by configured region
// Given a catalog with endpoints for "RegionOne" and "RegionTwo"
// And the configured region is "RegionOne"
// When the catalog is loaded
// Then only "RegionOne" endpoints are retained
func TestAuthenticate_FiltersByRegion(t *testing.T) {
	ks := newKeystoneServer(t)
	ks.catalog = catalogWith(
		serviceEntry("compute",
			endpoint("public", "RegionOne", "http://compute-region1.example.com"),
		),
		serviceEntry("network",
			endpoint("public", "RegionTwo", "http://network-region2.example.com"),
		),
	)

	clouds := buildCloudsYAMLWithRegion(ks.URL, "RegionOne")
	session, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !session.HasEndpoint("compute") {
		t.Error("expected compute endpoint (RegionOne) to be present")
	}
	if session.HasEndpoint("network") {
		t.Error("expected network endpoint (RegionTwo) to be absent when region is RegionOne")
	}
}

// Scenario: No region configured
// Given a catalog with endpoints in multiple regions
// And no region is configured
// When the catalog is loaded
// Then the first endpoint matching the interface is retained for each service
func TestAuthenticate_NoRegionFilter_AcceptsAllRegions(t *testing.T) {
	ks := newKeystoneServer(t)
	ks.catalog = catalogWith(
		serviceEntry("compute",
			endpoint("public", "RegionOne", "http://compute-region1.example.com"),
		),
		serviceEntry("network",
			endpoint("public", "RegionTwo", "http://network-region2.example.com"),
		),
	)

	clouds := buildCloudsYAMLWithRegion(ks.URL, "") // no region
	session, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !session.HasEndpoint("compute") {
		t.Error("expected compute endpoint to be present when no region filter")
	}
	if !session.HasEndpoint("network") {
		t.Error("expected network endpoint to be present when no region filter")
	}
}

// Scenario: Catalog with multiple services
func TestAuthenticate_MultipleServicesInCatalog(t *testing.T) {
	ks := newKeystoneServer(t)
	ks.catalog = catalogWith(
		serviceEntry("compute",
			endpoint("public", "RegionOne", "http://compute.example.com"),
		),
		serviceEntry("network",
			endpoint("public", "RegionOne", "http://network.example.com"),
		),
		serviceEntry("identity",
			endpoint("public", "RegionOne", "http://identity.example.com"),
		),
	)

	clouds := buildCloudsYAML(ks.URL, "v3applicationcredential")
	session, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, svc := range []string{"compute", "network", "identity"} {
		if !session.HasEndpoint(svc) {
			t.Errorf("expected endpoint %q to be present", svc)
		}
	}
}

// Scenario: Empty catalog → unauthenticated
func TestAuthenticate_EmptyCatalog_NotAuthenticated(t *testing.T) {
	ks := newKeystoneServer(t)
	ks.catalog = catalogWith() // no services

	clouds := buildCloudsYAML(ks.URL, "v3applicationcredential")
	session, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session.IsAuthenticated() {
		t.Error("expected session to be unauthenticated with empty catalog")
	}
}

// ── US1.4: Custom CA certificate support ────────────────────────────────────

// Scenario: CA provided in the Kubernetes secret
// Given a Kubernetes secret containing a "cacert" entry
// When the operator initialises the TLS transport
// Then the CA is loaded into the SSL context
// And HTTPS calls to OpenStack use this CA for verification
func TestAuthenticate_WithCustomCACert(t *testing.T) {
	ks := newTLSKeystoneServer(t)
	ks.catalog = catalogWith(
		serviceEntry("compute",
			endpoint("public", "RegionOne", "http://compute.example.com"),
		),
	)

	// Extract the server's self-signed certificate as PEM.
	tlsConfig := ks.Server.TLS
	rawCert := tlsConfig.Certificates[0].Certificate[0]
	x509Cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		t.Fatalf("parsing server cert: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: x509Cert.Raw,
	}))

	clouds := buildCloudsYAML(ks.URL, "v3applicationcredential")
	session, err := openstack.Authenticate(context.Background(), clouds, "openstack", certPEM)

	if err != nil {
		t.Fatalf("expected no error with custom CA, got: %v", err)
	}
	if !session.IsAuthenticated() {
		t.Error("expected authenticated session with valid custom CA cert")
	}
}

// Scenario: No CA provided → system CA used (plain HTTP connection must work)
func TestAuthenticate_NoCACert_HTTPServerWorks(t *testing.T) {
	ks := newKeystoneServer(t) // plain HTTP
	ks.catalog = catalogWith(
		serviceEntry("compute",
			endpoint("public", "RegionOne", "http://compute.example.com"),
		),
	)

	clouds := buildCloudsYAML(ks.URL, "v3applicationcredential")
	session, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")

	if err != nil {
		t.Fatalf("unexpected error without CA cert: %v", err)
	}
	if !session.IsAuthenticated() {
		t.Error("expected authenticated session")
	}
}

// Scenario: CA provided but invalid → TLS must fail
func TestAuthenticate_InvalidCACert_TLSFails(t *testing.T) {
	ks := newTLSKeystoneServer(t)

	clouds := buildCloudsYAML(ks.URL, "v3applicationcredential")
	// Pass a wrong/empty CA cert → TLS verification should fail.
	_, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")

	if err == nil {
		t.Fatal("expected TLS error without correct CA cert, got nil")
	}
}

// ── AppCredentialID ─────────────────────────────────────────────────────────

// Scenario: Extracting application credential ID from clouds.yaml
func TestAppCredentialID_Found(t *testing.T) {
	clouds := `
clouds:
  mycloud:
    auth_type: v3applicationcredential
    auth:
      auth_url: https://keystone.example.com/v3
      application_credential_id: my-appcred-id-xyz
      application_credential_secret: secret123
`
	id, err := openstack.AppCredentialID(clouds, "mycloud")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "my-appcred-id-xyz" {
		t.Errorf("expected %q, got %q", "my-appcred-id-xyz", id)
	}
}

// Scenario: Cloud absent → error
func TestAppCredentialID_CloudNotFound(t *testing.T) {
	clouds := `
clouds:
  openstack:
    auth_type: v3applicationcredential
    auth:
      auth_url: https://keystone.example.com/v3
      application_credential_id: some-id
      application_credential_secret: secret
`
	_, err := openstack.AppCredentialID(clouds, "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing cloud, got nil")
	}
}

// ── Error types ─────────────────────────────────────────────────────────────

func TestAuthenticationError_Message(t *testing.T) {
	err := &openstack.AuthenticationError{UserID: "user-abc"}
	expected := "failed to authenticate as user: user-abc"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestUnsupportedAuthTypeError_Message(t *testing.T) {
	err := &openstack.UnsupportedAuthTypeError{AuthType: "password"}
	expected := "unsupported authentication type: password"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestCatalogError_Message(t *testing.T) {
	err := &openstack.CatalogError{ServiceType: "volumev3"}
	expected := "service type volumev3 not found in OpenStack service catalog"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

// ── TLS verification ────────────────────────────────────────────────────────

// certPoolFromPEM builds an x509.CertPool from a PEM string (helper for assertions).
func certPoolFromPEM(pemData string) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(pemData))
	return pool
}

// tlsFromServer extracts TLS config from a test server (for CA assertions).
func tlsFromServer(s *httptest.Server) *tls.Config {
	return s.TLS
}

// errorAs is a typed helper to avoid importing errors package in test helpers.
func errorAs[T error](err error, target *T) bool {
	if t, ok := err.(T); ok {
		*target = t
		return true
	}
	return false
}
