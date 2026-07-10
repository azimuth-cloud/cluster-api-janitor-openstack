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
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

const (
	// KeepProperty is the OpenStack volume metadata key that marks a volume as user-kept.
	KeepProperty = "janitor.capi.azimuth-cloud.com/keep"

	// authTypeAppCred is the clouds.yaml auth_type for application credentials.
	authTypeAppCred = "v3applicationcredential"
	// authTypePassword is the clouds.yaml auth_type for username/password auth.
	authTypePassword = "v3password"
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

	// Username/password (v3password) fields.
	Username          string `yaml:"username"            json:"username"`
	UserID            string `yaml:"user_id"             json:"user_id"`
	Password          string `yaml:"password"            json:"password"`
	ProjectID         string `yaml:"project_id"          json:"project_id"`
	ProjectName       string `yaml:"project_name"        json:"project_name"`
	UserDomainName    string `yaml:"user_domain_name"    json:"user_domain_name"`
	UserDomainID      string `yaml:"user_domain_id"      json:"user_domain_id"`
	ProjectDomainName string `yaml:"project_domain_name" json:"project_domain_name"`
	ProjectDomainID   string `yaml:"project_domain_id"   json:"project_domain_id"`
	DomainName        string `yaml:"domain_name"         json:"domain_name"`
	DomainID          string `yaml:"domain_id"           json:"domain_id"`
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
	// SleepFunc is called instead of time.Sleep for polling waits.
	// A nil value defaults to time.Sleep.
	SleepFunc func(time.Duration)
}

// sleep calls SleepFunc if set, otherwise time.Sleep.
func (s *Session) sleep(d time.Duration) {
	if s.SleepFunc != nil {
		s.SleepFunc(d)
	} else {
		time.Sleep(d)
	}
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
	authType, err := resolveAuthType(entry)
	if err != nil {
		return nil, err
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
	if err := s.getToken(ctx, baseURL, authType, entry.Auth); err != nil {
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

// resolveAuthType determines the effective auth type for a cloud entry.
// It honours an explicit auth_type, and otherwise infers it from the auth
// block (application credential fields imply v3applicationcredential, a
// username/user_id implies v3password) to match common clouds.yaml usage
// where auth_type is omitted.
func resolveAuthType(entry cloudEntry) (string, error) {
	switch entry.AuthType {
	case authTypeAppCred, authTypePassword:
		return entry.AuthType, nil
	case "", "password":
		// Infer from the auth block for empty or ambiguous "password" values.
		if entry.Auth.ApplicationCredentialID != "" || entry.Auth.ApplicationCredentialSecret != "" {
			return authTypeAppCred, nil
		}
		if entry.Auth.Username != "" || entry.Auth.UserID != "" {
			return authTypePassword, nil
		}
		return "", &UnsupportedAuthTypeError{AuthType: entry.AuthType}
	default:
		return "", &UnsupportedAuthTypeError{AuthType: entry.AuthType}
	}
}

// passwordScope builds the Keystone auth scope from the auth block, preferring
// project scoping and falling back to domain scoping when set.
func passwordScope(auth authBlock) map[string]any {
	if auth.ProjectID != "" || auth.ProjectName != "" {
		project := map[string]any{}
		if auth.ProjectID != "" {
			project["id"] = auth.ProjectID
		} else {
			project["name"] = auth.ProjectName
			domain := map[string]any{}
			switch {
			case auth.ProjectDomainID != "":
				domain["id"] = auth.ProjectDomainID
			case auth.ProjectDomainName != "":
				domain["name"] = auth.ProjectDomainName
			case auth.UserDomainID != "":
				domain["id"] = auth.UserDomainID
			case auth.UserDomainName != "":
				domain["name"] = auth.UserDomainName
			}
			if len(domain) > 0 {
				project["domain"] = domain
			}
		}
		return map[string]any{"project": project}
	}
	if auth.DomainID != "" {
		return map[string]any{"domain": map[string]any{"id": auth.DomainID}}
	}
	if auth.DomainName != "" {
		return map[string]any{"domain": map[string]any{"name": auth.DomainName}}
	}
	return nil
}

// passwordTokenBody builds the Keystone token request body for v3password auth.
func passwordTokenBody(auth authBlock) map[string]any {
	user := map[string]any{"password": auth.Password}
	if auth.UserID != "" {
		user["id"] = auth.UserID
	} else {
		user["name"] = auth.Username
		domain := map[string]any{}
		if auth.UserDomainID != "" {
			domain["id"] = auth.UserDomainID
		} else if auth.UserDomainName != "" {
			domain["name"] = auth.UserDomainName
		}
		if len(domain) > 0 {
			user["domain"] = domain
		}
	}
	identity := map[string]any{
		"methods":  []string{"password"},
		"password": map[string]any{"user": user},
	}
	authReq := map[string]any{"identity": identity}
	if scope := passwordScope(auth); scope != nil {
		authReq["scope"] = scope
	}
	return map[string]any{"auth": authReq}
}

// appCredTokenBody builds the Keystone token request body for application credential auth.
func appCredTokenBody(auth authBlock) map[string]any {
	return map[string]any{
		"auth": map[string]any{
			"identity": map[string]any{
				"methods": []string{"application_credential"},
				"application_credential": map[string]any{
					"id":     auth.ApplicationCredentialID,
					"secret": auth.ApplicationCredentialSecret,
				},
			},
		},
	}
}

func (s *Session) getToken(ctx context.Context, baseURL, authType string, auth authBlock) error {
	var payload map[string]any
	if authType == authTypePassword {
		payload = passwordTokenBody(auth)
	} else {
		payload = appCredTokenBody(auth)
	}
	body, _ := json.Marshal(payload)
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

func (e *httpStatusError) Error() string   { return fmt.Sprintf("HTTP %d", e.code) }
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
