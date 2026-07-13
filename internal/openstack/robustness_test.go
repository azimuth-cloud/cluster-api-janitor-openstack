package openstack_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/azimuth-cloud/cluster-api-janitor-openstack/internal/openstack"
)

// ── US12.1 : Timeout HTTP ─────────────────────────────────────────────────────

// Scenario: context already cancelled → Authenticate returns an error immediately
func TestAuthenticate_ReturnsError_WhenContextAlreadyCancelled(t *testing.T) {
	// Use a real (if short-lived) server so Authenticate reaches the HTTP call.
	ks := newKeystoneServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call

	cloudsYAML := fmt.Sprintf(`
clouds:
  openstack:
    auth_type: v3applicationcredential
    auth:
      auth_url: %s
      application_credential_id: cred-id
      application_credential_secret: cred-secret
`, ks.URL)

	_, err := openstack.Authenticate(ctx, cloudsYAML, "openstack", "")
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

// ── US12.2 : Alias Cinder ────────────────────────────────────────────────────

// cinderAliasServer is a minimal Cinder mock that advertises a configurable
// service type in the catalog (allows testing "volume", "block-storage", etc.).
type cinderAliasServer struct {
	*httptest.Server
	mu             sync.Mutex
	volumeGetCount int
}

func newCinderAliasServer(t *testing.T, serviceType string) *cinderAliasServer {
	t.Helper()
	srv := &cinderAliasServer{}
	mux := http.NewServeMux()

	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("X-Subject-Token", "test-alias-token")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": map[string]any{"user": map[string]any{"id": "test-user"}},
		})
	})

	mux.HandleFunc("/v3/auth/catalog", func(w http.ResponseWriter, r *http.Request) {
		selfURL := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"catalog": []any{
				map[string]any{
					"type": serviceType, // "volume", "block-storage", …
					"endpoints": []any{
						map[string]any{
							"interface": "public",
							"region_id": "RegionOne",
							"url":       selfURL,
						},
					},
				},
			},
		})
	})

	mux.HandleFunc("/volumes/detail", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		srv.mu.Lock()
		srv.volumeGetCount++
		srv.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"volumes": []any{}})
	})

	srv.Server = httptest.NewServer(mux)
	t.Cleanup(srv.Server.Close)
	return srv
}

func (srv *cinderAliasServer) authenticate(t *testing.T) *openstack.Session {
	t.Helper()
	cloudsYAML := fmt.Sprintf(`
clouds:
  openstack:
    auth_type: v3applicationcredential
    auth:
      auth_url: %s
      application_credential_id: cred-id
      application_credential_secret: cred-secret
`, srv.URL)
	session, err := openstack.Authenticate(context.Background(), cloudsYAML, "openstack", "")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !session.IsAuthenticated() {
		t.Fatal("expected authenticated session")
	}
	session.SleepFunc = func(d time.Duration) {}
	return session
}

// Scenario: catalog with "block-storage" → cinderEndpoint resolves the correct endpoint
func TestCinderEndpoint_FallsBackToBlockStorage(t *testing.T) {
	srv := newCinderAliasServer(t, "block-storage")
	session := srv.authenticate(t)

	err := session.DeleteVolumes(context.Background(), logr.Discard(), "test-cluster")
	if err != nil {
		t.Fatalf("DeleteVolumes with block-storage catalog: %v", err)
	}
	if srv.volumeGetCount == 0 {
		t.Error("expected at least one GET /volumes/detail call")
	}
}

// Scenario: catalog with "volume" only → cinderEndpoint uses the legacy alias
func TestCinderEndpoint_FallsBackToVolumeAlias(t *testing.T) {
	srv := newCinderAliasServer(t, "volume")
	session := srv.authenticate(t)

	err := session.DeleteVolumes(context.Background(), logr.Discard(), "test-cluster")
	if err != nil {
		t.Fatalf("DeleteVolumes with volume alias catalog: %v", err)
	}
	if srv.volumeGetCount == 0 {
		t.Error("expected at least one GET /volumes/detail call")
	}
}
