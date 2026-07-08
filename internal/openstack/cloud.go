// Package openstack provides OpenStack client utilities and resource cleanup
// logic for the cluster-api-janitor-openstack operator.
package openstack

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
	"strings"

	"sigs.k8s.io/yaml"
)

const (
	// KeepProperty is the OpenStack volume metadata key that marks a volume as user-kept.
	KeepProperty = "janitor.capi.azimuth-cloud.com/keep"
)

// AuthenticationError is returned when OpenStack authentication fails.
type AuthenticationError struct {
	UserID string
}

func (e *AuthenticationError) Error() string {
	return fmt.Sprintf("failed to authenticate as user: %s", e.UserID)
}

// UnsupportedAuthTypeError is returned when clouds.yaml uses an unsupported auth type.
type UnsupportedAuthTypeError struct {
	AuthType string
}

func (e *UnsupportedAuthTypeError) Error() string {
	return fmt.Sprintf("unsupported authentication type: %s", e.AuthType)
}

// CatalogError is returned when a required service is absent from the OpenStack catalog.
type CatalogError struct {
	ServiceType string
}

func (e *CatalogError) Error() string {
	return fmt.Sprintf("service type %s not found in OpenStack service catalog", e.ServiceType)
}

// cloudsFile represents a minimal clouds.yaml structure.
type cloudsFile struct {
	Clouds map[string]cloudEntry `yaml:"clouds" json:"clouds"`
}

type cloudEntry struct {
	AuthType  string    `yaml:"auth_type"   json:"auth_type"`
	Auth      authBlock `yaml:"auth"         json:"auth"`
	Region    string    `yaml:"region_name"  json:"region_name"`
	Interface string    `yaml:"interface"    json:"interface"`
}

type authBlock struct {
	AuthURL                     string `yaml:"auth_url"                      json:"auth_url"`
	ApplicationCredentialID     string `yaml:"application_credential_id"     json:"application_credential_id"`
	ApplicationCredentialSecret string `yaml:"application_credential_secret" json:"application_credential_secret"`
}

// parseCloudsYAML parses a clouds.yaml string into a cloudsFile.
func parseCloudsYAML(data string) (*cloudsFile, error) {
	var cf cloudsFile
	if err := yaml.Unmarshal([]byte(data), &cf); err != nil {
		return nil, fmt.Errorf("parsing clouds.yaml: %w", err)
	}
	return &cf, nil
}

// authURLBase strips any trailing /v3 path segment.
var v3Suffix = regexp.MustCompile(`/v3/?$`)

func authURLBase(raw string) string {
	return v3Suffix.ReplaceAllString(raw, "")
}

// Session holds an authenticated OpenStack session with discovered endpoints.
type Session struct {
	token         string
	userID        string
	endpoints     map[string]string
	httpClient    *http.Client
	authenticated bool
}

// IsAuthenticated reports whether the session has a valid token and catalog.
func (s *Session) IsAuthenticated() bool { return s.authenticated }

// UserID returns the ID of the authenticated user.
func (s *Session) UserID() string { return s.userID }

// HasEndpoint reports whether the session has a discovered endpoint for the given service type.
func (s *Session) HasEndpoint(serviceType string) bool {
	_, ok := s.endpoints[serviceType]
	return ok
}

// Authenticate performs token authentication against Keystone and discovers
// the service catalog, returning a ready-to-use Session.
func Authenticate(ctx context.Context, cloudsYAML, cloudName, cacert string) (*Session, error) {
	cf, err := parseCloudsYAML(cloudsYAML)
	if err != nil {
		return nil, err
	}
	entry, ok := cf.Clouds[cloudName]
	if !ok {
		return nil, fmt.Errorf("cloud %q not found in clouds.yaml", cloudName)
	}
	if entry.AuthType != "v3applicationcredential" {
		return nil, &UnsupportedAuthTypeError{AuthType: entry.AuthType}
	}

	tlsCfg := &tls.Config{} //nolint:gosec
	if cacert != "" {
		if err := loadCACert(tlsCfg, cacert); err != nil {
			return nil, err
		}
	}
	hc := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   30 * time.Second,
	}

	iface := entry.Interface
	if iface == "" {
		iface = "public"
	}
	baseURL := authURLBase(entry.Auth.AuthURL)

	s := &Session{httpClient: hc}
	if err := s.getToken(ctx, baseURL, entry.Auth); err != nil {
		if isHTTP(err, http.StatusNotFound) {
			return s, nil // deleted appcred case: unauthenticated, no fatal error
		}
		return nil, err
	}
	if err := s.loadCatalog(ctx, baseURL, iface, entry.Region); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Session) getToken(ctx context.Context, baseURL string, auth authBlock) error {
	body, _ := json.Marshal(map[string]any{
		"auth": map[string]any{
			"identity": map[string]any{
				"methods": []string{"application_credential"},
				"application_credential": map[string]any{
					"id":     auth.ApplicationCredentialID,
					"secret": auth.ApplicationCredentialSecret,
				},
			},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/v3/auth/tokens", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return &httpStatusError{code: resp.StatusCode}
	}
	s.token = resp.Header.Get("X-Subject-Token")
	var result struct {
		Token struct {
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	s.userID = result.Token.User.ID
	return nil
}

func (s *Session) loadCatalog(ctx context.Context, baseURL, iface, region string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		baseURL+"/v3/auth/catalog", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Auth-Token", s.token)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode >= 400 {
		return &httpStatusError{code: resp.StatusCode}
	}
	var catalog struct {
		Catalog []struct {
			Type      string `json:"type"`
			Endpoints []struct {
				Interface string `json:"interface"`
				RegionID  string `json:"region_id"`
				URL       string `json:"url"`
			} `json:"endpoints"`
		} `json:"catalog"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return err
	}
	s.endpoints = make(map[string]string)
	for _, entry := range catalog.Catalog {
		for _, ep := range entry.Endpoints {
			if ep.Interface != iface {
				continue
			}
			if region != "" && ep.RegionID != region {
				continue
			}
			s.endpoints[entry.Type] = ep.URL
			break
		}
	}
	if len(s.endpoints) > 0 {
		s.authenticated = true
	}
	return nil
}

func (s *Session) endpointFor(serviceTypes ...string) (string, error) {
	for _, st := range serviceTypes {
		if u, ok := s.endpoints[st]; ok {
			return u, nil
		}
	}
	return "", &CatalogError{ServiceType: strings.Join(serviceTypes, " or ")}
}

// doGet issues an authenticated GET and returns the response body.
func (s *Session) doGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", s.token)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, &httpStatusError{code: resp.StatusCode}
	}
	return io.ReadAll(resp.Body)
}

// doDelete issues an authenticated DELETE request.
func (s *Session) doDelete(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Auth-Token", s.token)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode >= 400 {
		return &httpStatusError{code: resp.StatusCode}
	}
	return nil
}

type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return fmt.Sprintf("HTTP %d", e.code) }
func (e *httpStatusError) StatusCode() int { return e.code }

func isHTTP(err error, code int) bool {
	var he *httpStatusError
	if errors.As(err, &he) {
		return he.code == code
	}
	return false
}

// isTransient returns true for HTTP 400 and 409 (conflict/bad-request = retry).
func isTransient(err error) bool {
	var he *httpStatusError
	if errors.As(err, &he) {
		return he.code == http.StatusBadRequest || he.code == http.StatusConflict
	}
	return false
}

// AppCredentialID extracts the application_credential_id from a clouds.yaml string.
func AppCredentialID(cloudsYAML, cloudName string) (string, error) {
	cf, err := parseCloudsYAML(cloudsYAML)
	if err != nil {
		return "", err
	}
	entry, ok := cf.Clouds[cloudName]
	if !ok {
		return "", fmt.Errorf("cloud %q not found", cloudName)
	}
	return entry.Auth.ApplicationCredentialID, nil
}
