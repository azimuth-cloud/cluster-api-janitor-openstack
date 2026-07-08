package openstack_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"

	"github.com/azimuth-cloud/cluster-api-janitor-openstack/internal/openstack"
)

// ── Mock server ───────────────────────────────────────────────────────────────

// fipRecord represents a Neutron floating IP in list responses.
type fipRecord struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// networkTestServer is a mock OpenStack server that handles Keystone auth +
// a Neutron-like API on the same HTTP test server. The catalog advertises the
// server's own URL as the "network" endpoint, so Sessions authenticate and
// resolve resource URLs against this single server.
type networkTestServer struct {
	*httptest.Server
	mu          sync.Mutex
	fipLists    [][]fipRecord // sequence of list responses; last entry is reused
	fipGetCount int           // total number of GET /v2.0/floatingips calls
	// Per-FIP DELETE response status (default 204 NoContent).
	deleteStatus map[string]int
	// IDs deleted in call order.
	deletedFIPs []string
}

func newNetworkTestServer(t *testing.T) *networkTestServer {
	t.Helper()
	srv := &networkTestServer{
		deleteStatus: make(map[string]int),
	}
	mux := http.NewServeMux()

	// Keystone: token endpoint
	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("X-Subject-Token", "test-network-token")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": map[string]any{"user": map[string]any{"id": "test-user"}},
		})
	})

	// Keystone: service catalog — self-referential: "network" endpoint = this server
	mux.HandleFunc("/v3/auth/catalog", func(w http.ResponseWriter, r *http.Request) {
		selfURL := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"catalog": []any{
				map[string]any{
					"type": "network",
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

	// Neutron: list floating IPs (exact path — no trailing slash to avoid redirect)
	mux.HandleFunc("/v2.0/floatingips", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		srv.mu.Lock()
		srv.fipGetCount++
		idx := srv.fipGetCount - 1
		var list []fipRecord
		if len(srv.fipLists) > 0 {
			if idx < len(srv.fipLists) {
				list = srv.fipLists[idx]
			} else {
				list = srv.fipLists[len(srv.fipLists)-1]
			}
		}
		srv.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"floatingips": list})
	})

	// Neutron: delete floating IP by ID (subtree pattern handles /v2.0/floatingips/{id})
	mux.HandleFunc("/v2.0/floatingips/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v2.0/floatingips/")
		srv.mu.Lock()
		srv.deletedFIPs = append(srv.deletedFIPs, id)
		status, ok := srv.deleteStatus[id]
		if !ok {
			status = http.StatusNoContent
		}
		srv.mu.Unlock()
		w.WriteHeader(status)
	})

	srv.Server = httptest.NewServer(mux)
	t.Cleanup(srv.Server.Close)
	return srv
}

// authenticate creates an authenticated Session against this server.
func (srv *networkTestServer) authenticate(t *testing.T) *openstack.Session {
	t.Helper()
	cloudsYAML := fmt.Sprintf(`
clouds:
  openstack:
    auth_type: v3applicationcredential
    auth:
      auth_url: %s
      application_credential_id: test-id
      application_credential_secret: test-secret
    interface: public
    region_name: RegionOne
`, srv.URL)
	session, err := openstack.Authenticate(context.Background(), cloudsYAML, "openstack", "")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !session.IsAuthenticated() {
		t.Fatal("expected authenticated session with network endpoint")
	}
	return session
}

// fipDesc returns the description that OCCM writes for a service FIP.
func fipDesc(cluster string) string {
	return fmt.Sprintf("Floating IP for Kubernetes external service from cluster %s", cluster)
}

// ── LB mock server ───────────────────────────────────────────────────────────

type lbRecord struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// lbTestServer is a mock OpenStack server that handles Keystone auth +
// an Octavia-like API on the same HTTP test server. The catalog advertises the
// server's own URL as the "load-balancer" endpoint.
type lbTestServer struct {
	*httptest.Server
	mu                 sync.Mutex
	lbLists            [][]lbRecord
	lbGetCount         int
	listStatusOverride int // if non-zero, all GET /v2/lbaas/loadbalancers return this status
	deleteStatus       map[string]int
	deletedLBs         []string
	deleteCascade      []string // cascade query param value per DELETE call
}

func newLBTestServer(t *testing.T) *lbTestServer {
	t.Helper()
	srv := &lbTestServer{
		deleteStatus: make(map[string]int),
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("X-Subject-Token", "test-lb-token")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": map[string]any{"user": map[string]any{"id": "test-user"}},
		})
	})

	// Self-referential catalog: "load-balancer" endpoint = this server.
	mux.HandleFunc("/v3/auth/catalog", func(w http.ResponseWriter, r *http.Request) {
		selfURL := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"catalog": []any{
				map[string]any{
					"type": "load-balancer",
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

	mux.HandleFunc("/v2/lbaas/loadbalancers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		srv.mu.Lock()
		override := srv.listStatusOverride
		srv.lbGetCount++
		idx := srv.lbGetCount - 1
		var list []lbRecord
		if len(srv.lbLists) > 0 {
			if idx < len(srv.lbLists) {
				list = srv.lbLists[idx]
			} else {
				list = srv.lbLists[len(srv.lbLists)-1]
			}
		}
		srv.mu.Unlock()
		if override != 0 {
			w.WriteHeader(override)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"loadbalancers": list})
	})

	mux.HandleFunc("/v2/lbaas/loadbalancers/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v2/lbaas/loadbalancers/")
		cascade := r.URL.Query().Get("cascade")
		srv.mu.Lock()
		srv.deletedLBs = append(srv.deletedLBs, id)
		srv.deleteCascade = append(srv.deleteCascade, cascade)
		status, ok := srv.deleteStatus[id]
		if !ok {
			status = http.StatusNoContent
		}
		srv.mu.Unlock()
		w.WriteHeader(status)
	})

	srv.Server = httptest.NewServer(mux)
	t.Cleanup(srv.Server.Close)
	return srv
}

func (srv *lbTestServer) authenticate(t *testing.T) *openstack.Session {
	t.Helper()
	cloudsYAML := fmt.Sprintf(`
clouds:
  openstack:
    auth_type: v3applicationcredential
    auth:
      auth_url: %s
      application_credential_id: test-id
      application_credential_secret: test-secret
    interface: public
    region_name: RegionOne
`, srv.URL)
	session, err := openstack.Authenticate(context.Background(), cloudsYAML, "openstack", "")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return session
}

func lbKubeName(cluster, suffix string) string {
	return fmt.Sprintf("kube_service_%s_%s", cluster, suffix)
}

// ── US2.1: Identifier les Floating IPs d'un cluster ──────────────────────────

// Scenario: FIP appartenant au cluster → incluse dans la suppression
// Scenario: FIP d'un autre cluster → exclue
// Scenario: FIP sans description Kubernetes → exclue
func TestDeleteFloatingIPs_Filtering(t *testing.T) {
	tests := []struct {
		name         string
		description  string
		cluster      string
		shouldDelete bool
	}{
		{
			name:         "matching cluster",
			description:  fipDesc("mycluster"),
			cluster:      "mycluster",
			shouldDelete: true,
		},
		{
			name:         "different cluster",
			description:  fipDesc("othercluster"),
			cluster:      "mycluster",
			shouldDelete: false,
		},
		{
			name:         "non-kubernetes description",
			description:  "Some unrelated floating IP",
			cluster:      "mycluster",
			shouldDelete: false,
		},
		{
			name:         "empty description",
			description:  "",
			cluster:      "mycluster",
			shouldDelete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newNetworkTestServer(t)
			fip := fipRecord{ID: "fip-001", Description: tt.description}
			// List: FIP present before deletion; empty after (verification passes)
			srv.fipLists = [][]fipRecord{{fip}, {}}

			session := srv.authenticate(t)
			if err := session.DeleteFloatingIPs(context.Background(), logr.Discard(), tt.cluster); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			srv.mu.Lock()
			deleted := len(srv.deletedFIPs) > 0
			srv.mu.Unlock()

			if deleted != tt.shouldDelete {
				t.Errorf("shouldDelete=%v but FIP was deleted=%v", tt.shouldDelete, deleted)
			}
		})
	}
}

// Scenario: FIPs de plusieurs clusters → seules celles du bon cluster sont supprimées
func TestDeleteFloatingIPs_MultipleIPsPartialMatch(t *testing.T) {
	srv := newNetworkTestServer(t)
	fips := []fipRecord{
		{ID: "fip-001", Description: fipDesc("mycluster")},   // match
		{ID: "fip-002", Description: fipDesc("othercluster")}, // no match
		{ID: "fip-003", Description: "Some other description"}, // no match
		{ID: "fip-004", Description: fipDesc("mycluster")},   // match
	}
	srv.fipLists = [][]fipRecord{fips, {}}

	session := srv.authenticate(t)
	if err := session.DeleteFloatingIPs(context.Background(), logr.Discard(), "mycluster"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	srv.mu.Lock()
	deleted := make(map[string]bool, len(srv.deletedFIPs))
	for _, id := range srv.deletedFIPs {
		deleted[id] = true
	}
	srv.mu.Unlock()

	if !deleted["fip-001"] || !deleted["fip-004"] {
		t.Errorf("expected fip-001 and fip-004 to be deleted, got: %v", srv.deletedFIPs)
	}
	if deleted["fip-002"] || deleted["fip-003"] {
		t.Errorf("expected fip-002 and fip-003 to NOT be deleted, got: %v", srv.deletedFIPs)
	}
}

// ── US2.2: Supprimer les Floating IPs ────────────────────────────────────────

// Scenario: Suppression réussie
// Given une FIP appartenant au cluster "mycluster"
// When la purge des FIPs est déclenchée
// Then la FIP est supprimée via l'API Neutron
func TestDeleteFloatingIPs_SuccessfulDeletion(t *testing.T) {
	srv := newNetworkTestServer(t)
	fips := []fipRecord{
		{ID: "fip-001", Description: fipDesc("mycluster")},
		{ID: "fip-002", Description: fipDesc("mycluster")},
	}
	srv.fipLists = [][]fipRecord{fips, {}} // first: FIPs present; verification: empty

	session := srv.authenticate(t)
	if err := session.DeleteFloatingIPs(context.Background(), logr.Discard(), "mycluster"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	srv.mu.Lock()
	deletedIDs := srv.deletedFIPs
	srv.mu.Unlock()

	if len(deletedIDs) != 2 {
		t.Errorf("expected 2 FIPs deleted, got %d: %v", len(deletedIDs), deletedIDs)
	}
	idSet := make(map[string]bool)
	for _, id := range deletedIDs {
		idSet[id] = true
	}
	for _, fip := range fips {
		if !idSet[fip.ID] {
			t.Errorf("expected FIP %s to be deleted", fip.ID)
		}
	}
}

// Scenario: Erreur HTTP 400 lors de la suppression
// Then un warning est émis
// And la suppression continue pour les autres FIPs
// And vérification déclenchée (check_fips = true)
func TestDeleteFloatingIPs_TransientError400_ContinuesAndVerifies(t *testing.T) {
	srv := newNetworkTestServer(t)
	fips := []fipRecord{
		{ID: "fip-001", Description: fipDesc("mycluster")}, // returns HTTP 400
		{ID: "fip-002", Description: fipDesc("mycluster")}, // returns HTTP 204
	}
	srv.fipLists = [][]fipRecord{fips, {}} // verification returns empty
	srv.deleteStatus["fip-001"] = http.StatusBadRequest

	session := srv.authenticate(t)
	err := session.DeleteFloatingIPs(context.Background(), logr.Discard(), "mycluster")

	// Transient error must NOT be propagated
	if err != nil {
		t.Fatalf("expected no error for transient HTTP 400, got: %v", err)
	}

	// Both FIPs must have been attempted
	srv.mu.Lock()
	attempted := len(srv.deletedFIPs)
	getCount := srv.fipGetCount
	srv.mu.Unlock()

	if attempted != 2 {
		t.Errorf("expected both FIPs to be attempted, got %d DELETE calls", attempted)
	}
	// Verification GET must have been triggered (deleted=true even on transient error)
	if getCount < 2 {
		t.Errorf("expected at least 2 GET calls (list + verification), got %d", getCount)
	}
}

// Scenario: Erreur HTTP 409 (Conflict) → même comportement que 400
func TestDeleteFloatingIPs_TransientError409_Continues(t *testing.T) {
	srv := newNetworkTestServer(t)
	fips := []fipRecord{
		{ID: "fip-conflict", Description: fipDesc("mycluster")},
	}
	srv.fipLists = [][]fipRecord{fips, {}}
	srv.deleteStatus["fip-conflict"] = http.StatusConflict

	session := srv.authenticate(t)
	if err := session.DeleteFloatingIPs(context.Background(), logr.Discard(), "mycluster"); err != nil {
		t.Fatalf("expected no error for transient HTTP 409, got: %v", err)
	}
}

// Scenario: Erreur HTTP 500 → exception propagée
func TestDeleteFloatingIPs_HTTP500_PropagatesError(t *testing.T) {
	srv := newNetworkTestServer(t)
	fips := []fipRecord{
		{ID: "fip-server-error", Description: fipDesc("mycluster")},
	}
	srv.fipLists = [][]fipRecord{fips}
	srv.deleteStatus["fip-server-error"] = http.StatusInternalServerError

	session := srv.authenticate(t)
	err := session.DeleteFloatingIPs(context.Background(), logr.Discard(), "mycluster")

	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

// Scenario: FIPs toujours présentes après suppression → erreur retournée
// (le contrôleur réessaiera via l'annotation retry)
func TestDeleteFloatingIPs_StillPresentAfterDeletion_ReturnsError(t *testing.T) {
	srv := newNetworkTestServer(t)
	fip := fipRecord{ID: "fip-persistent", Description: fipDesc("mycluster")}
	// Verification also returns the FIP — OpenStack has not deleted it yet
	srv.fipLists = [][]fipRecord{{fip}, {fip}}

	session := srv.authenticate(t)
	err := session.DeleteFloatingIPs(context.Background(), logr.Discard(), "mycluster")

	if err == nil {
		t.Fatal("expected error when FIP persists after deletion")
	}
	if !strings.Contains(err.Error(), "mycluster") {
		t.Errorf("expected error to mention cluster name, got: %v", err)
	}
}

// Scenario: Aucune FIP correspondante → pas de suppression, pas de vérification
func TestDeleteFloatingIPs_NothingToDelete_NoVerification(t *testing.T) {
	srv := newNetworkTestServer(t)
	srv.fipLists = [][]fipRecord{{}} // empty list

	session := srv.authenticate(t)
	if err := session.DeleteFloatingIPs(context.Background(), logr.Discard(), "mycluster"); err != nil {
		t.Fatalf("unexpected error with no FIPs: %v", err)
	}

	srv.mu.Lock()
	deletedCount := len(srv.deletedFIPs)
	getCount := srv.fipGetCount
	srv.mu.Unlock()

	if deletedCount != 0 {
		t.Errorf("expected no DELETE calls, got %d: %v", deletedCount, srv.deletedFIPs)
	}
	// No verification GET should be triggered when nothing was found
	if getCount != 1 {
		t.Errorf("expected exactly 1 GET call (no verification), got %d", getCount)
	}
}

// Scenario: Pas d'endpoint "network" dans le catalogue → CatalogError
func TestDeleteFloatingIPs_NoNetworkEndpoint_ReturnsCatalogError(t *testing.T) {
	// Use a Keystone server that only advertises a "compute" endpoint (no "network")
	ks := newKeystoneServer(t)
	ks.catalog = catalogWith(
		serviceEntry("compute",
			endpoint("public", "RegionOne", "http://compute.example.com"),
		),
	)

	clouds := buildCloudsYAML(ks.URL, "v3applicationcredential")
	session, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")
	if err != nil {
		t.Fatalf("unexpected authenticate error: %v", err)
	}

	err = session.DeleteFloatingIPs(context.Background(), logr.Discard(), "mycluster")

	if err == nil {
		t.Fatal("expected CatalogError when network endpoint is absent")
	}
	var target *openstack.CatalogError
	if !errorAs(err, &target) {
		t.Errorf("expected *CatalogError, got %T: %v", err, err)
	}
}

// ── Epic 3: Nettoyage des Load Balancers Octavia ──────────────────────────────

// ── US3.1: Identifier les Load Balancers Kubernetes ──────────────────────────

// Scenario: LB appartenant au cluster → inclus dans la suppression
// Scenario: LB d'un autre cluster → exclu
// Scenario: LB sans préfixe kube_service → exclu
func TestDeleteLoadBalancers_Filtering(t *testing.T) {
	tests := []struct {
		name         string
		lbName       string
		cluster      string
		shouldDelete bool
	}{
		{
			name:         "matching cluster",
			lbName:       lbKubeName("mycluster", "api"),
			cluster:      "mycluster",
			shouldDelete: true,
		},
		{
			name:         "different cluster",
			lbName:       lbKubeName("othercluster", "api"),
			cluster:      "mycluster",
			shouldDelete: false,
		},
		{
			name:         "wrong prefix",
			lbName:       "fake_service_mycluster_api",
			cluster:      "mycluster",
			shouldDelete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newLBTestServer(t)
			lb := lbRecord{ID: "lb-001", Name: tt.lbName}
			srv.lbLists = [][]lbRecord{{lb}, {}}

			session := srv.authenticate(t)
			if err := session.DeleteLoadBalancers(context.Background(), logr.Discard(), tt.cluster); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			srv.mu.Lock()
			deleted := len(srv.deletedLBs) > 0
			srv.mu.Unlock()

			if deleted != tt.shouldDelete {
				t.Errorf("shouldDelete=%v but LB was deleted=%v", tt.shouldDelete, deleted)
			}
		})
	}
}

// ── US3.2: Erreur HTTP lors du listing (PR #261) ──────────────────────────────

// Scenario: Erreur HTTP lors du listing des LBs → log ERROR, pas d'exception
func TestDeleteLoadBalancers_ListError_LogsAndSkips(t *testing.T) {
	srv := newLBTestServer(t)
	srv.listStatusOverride = http.StatusInternalServerError

	session := srv.authenticate(t)
	err := session.DeleteLoadBalancers(context.Background(), logr.Discard(), "mycluster")

	if err != nil {
		t.Fatalf("expected nil when list returns HTTP 500, got: %v", err)
	}
	srv.mu.Lock()
	deleted := len(srv.deletedLBs)
	srv.mu.Unlock()
	if deleted != 0 {
		t.Errorf("expected no DELETE calls when list fails, got %d", deleted)
	}
}

// ── US3.3: Supprimer les Load Balancers en cascade ───────────────────────────

// Scenario: Suppression réussie avec cascade=true
func TestDeleteLoadBalancers_SuccessfulDeletion(t *testing.T) {
	srv := newLBTestServer(t)
	lbs := []lbRecord{
		{ID: "lb-001", Name: lbKubeName("mycluster", "svc1")},
		{ID: "lb-002", Name: lbKubeName("mycluster", "svc2")},
	}
	srv.lbLists = [][]lbRecord{lbs, {}}

	session := srv.authenticate(t)
	if err := session.DeleteLoadBalancers(context.Background(), logr.Discard(), "mycluster"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	srv.mu.Lock()
	deletedIDs := srv.deletedLBs
	srv.mu.Unlock()

	if len(deletedIDs) != 2 {
		t.Errorf("expected 2 LBs deleted, got %d: %v", len(deletedIDs), deletedIDs)
	}
	idSet := make(map[string]bool)
	for _, id := range deletedIDs {
		idSet[id] = true
	}
	for _, lb := range lbs {
		if !idSet[lb.ID] {
			t.Errorf("expected LB %s to be deleted", lb.ID)
		}
	}
}

// Scenario: DELETE émis avec cascade=true
func TestDeleteLoadBalancers_CascadeDelete(t *testing.T) {
	srv := newLBTestServer(t)
	srv.lbLists = [][]lbRecord{
		{{ID: "lb-cascade", Name: lbKubeName("mycluster", "svc")}},
		{},
	}

	session := srv.authenticate(t)
	if err := session.DeleteLoadBalancers(context.Background(), logr.Discard(), "mycluster"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	srv.mu.Lock()
	cascades := srv.deleteCascade
	srv.mu.Unlock()

	if len(cascades) == 0 {
		t.Fatal("expected a DELETE call, got none")
	}
	for i, c := range cascades {
		if c != "true" {
			t.Errorf("DELETE call %d: expected cascade=true, got %q", i, c)
		}
	}
}

// Scenario: Erreur HTTP 400 lors de la suppression → warning, continue, vérification déclenchée
func TestDeleteLoadBalancers_TransientError400_ContinuesAndVerifies(t *testing.T) {
	srv := newLBTestServer(t)
	lbs := []lbRecord{
		{ID: "lb-001", Name: lbKubeName("mycluster", "svc1")}, // returns HTTP 400
		{ID: "lb-002", Name: lbKubeName("mycluster", "svc2")}, // returns HTTP 204
	}
	srv.lbLists = [][]lbRecord{lbs, {}}
	srv.deleteStatus["lb-001"] = http.StatusBadRequest

	session := srv.authenticate(t)
	err := session.DeleteLoadBalancers(context.Background(), logr.Discard(), "mycluster")

	if err != nil {
		t.Fatalf("expected no error for transient HTTP 400, got: %v", err)
	}

	srv.mu.Lock()
	attempted := len(srv.deletedLBs)
	getCount := srv.lbGetCount
	srv.mu.Unlock()

	if attempted != 2 {
		t.Errorf("expected both LBs to be attempted, got %d DELETE calls", attempted)
	}
	if getCount < 2 {
		t.Errorf("expected at least 2 GET calls (list + verification), got %d", getCount)
	}
}

// Scenario: Erreur HTTP 500 → exception propagée
func TestDeleteLoadBalancers_HTTP500_PropagatesError(t *testing.T) {
	srv := newLBTestServer(t)
	srv.lbLists = [][]lbRecord{
		{{ID: "lb-server-error", Name: lbKubeName("mycluster", "svc")}},
	}
	srv.deleteStatus["lb-server-error"] = http.StatusInternalServerError

	session := srv.authenticate(t)
	err := session.DeleteLoadBalancers(context.Background(), logr.Discard(), "mycluster")

	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

// Scenario: LBs toujours présents après suppression → erreur retournée
func TestDeleteLoadBalancers_StillPresentAfterDeletion_ReturnsError(t *testing.T) {
	srv := newLBTestServer(t)
	lb := lbRecord{ID: "lb-persistent", Name: lbKubeName("mycluster", "svc")}
	srv.lbLists = [][]lbRecord{{lb}, {lb}}

	session := srv.authenticate(t)
	err := session.DeleteLoadBalancers(context.Background(), logr.Discard(), "mycluster")

	if err == nil {
		t.Fatal("expected error when LB persists after deletion")
	}
	if !strings.Contains(err.Error(), "mycluster") {
		t.Errorf("expected error to mention cluster name, got: %v", err)
	}
}

// Scenario: Aucun LB correspondant → pas de suppression, pas de vérification
func TestDeleteLoadBalancers_NothingToDelete_NoVerification(t *testing.T) {
	srv := newLBTestServer(t)
	srv.lbLists = [][]lbRecord{{}}

	session := srv.authenticate(t)
	if err := session.DeleteLoadBalancers(context.Background(), logr.Discard(), "mycluster"); err != nil {
		t.Fatalf("unexpected error with no LBs: %v", err)
	}

	srv.mu.Lock()
	deletedCount := len(srv.deletedLBs)
	getCount := srv.lbGetCount
	srv.mu.Unlock()

	if deletedCount != 0 {
		t.Errorf("expected no DELETE calls, got %d: %v", deletedCount, srv.deletedLBs)
	}
	if getCount != 1 {
		t.Errorf("expected exactly 1 GET call (no verification), got %d", getCount)
	}
}

// ── SG mock server ────────────────────────────────────────────────────────────

type sgRecord struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// sgTestServer is a mock OpenStack server that handles Keystone auth +
// a Neutron-like security group API. The catalog advertises the server's own
// URL as the "network" endpoint.
type sgTestServer struct {
	*httptest.Server
	mu                 sync.Mutex
	sgLists            [][]sgRecord
	sgGetCount         int
	listStatusOverride int // if non-zero, all GETs return this status
	deleteStatus       map[string]int
	deletedSGs         []string
}

func newSGTestServer(t *testing.T) *sgTestServer {
	t.Helper()
	srv := &sgTestServer{
		deleteStatus: make(map[string]int),
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("X-Subject-Token", "test-sg-token")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": map[string]any{"user": map[string]any{"id": "test-user"}},
		})
	})

	// Self-referential catalog: "network" endpoint = this server.
	mux.HandleFunc("/v3/auth/catalog", func(w http.ResponseWriter, r *http.Request) {
		selfURL := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"catalog": []any{
				map[string]any{
					"type": "network",
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

	mux.HandleFunc("/v2.0/security-groups", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		srv.mu.Lock()
		override := srv.listStatusOverride
		srv.sgGetCount++
		idx := srv.sgGetCount - 1
		var list []sgRecord
		if len(srv.sgLists) > 0 {
			if idx < len(srv.sgLists) {
				list = srv.sgLists[idx]
			} else {
				list = srv.sgLists[len(srv.sgLists)-1]
			}
		}
		srv.mu.Unlock()
		if override != 0 {
			w.WriteHeader(override)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"security_groups": list})
	})

	mux.HandleFunc("/v2.0/security-groups/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v2.0/security-groups/")
		srv.mu.Lock()
		srv.deletedSGs = append(srv.deletedSGs, id)
		status, ok := srv.deleteStatus[id]
		if !ok {
			status = http.StatusNoContent
		}
		srv.mu.Unlock()
		w.WriteHeader(status)
	})

	srv.Server = httptest.NewServer(mux)
	t.Cleanup(srv.Server.Close)
	return srv
}

func (srv *sgTestServer) authenticate(t *testing.T) *openstack.Session {
	t.Helper()
	cloudsYAML := fmt.Sprintf(`
clouds:
  openstack:
    auth_type: v3applicationcredential
    auth:
      auth_url: %s
      application_credential_id: test-id
      application_credential_secret: test-secret
    interface: public
    region_name: RegionOne
`, srv.URL)
	session, err := openstack.Authenticate(context.Background(), cloudsYAML, "openstack", "")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !session.IsAuthenticated() {
		t.Fatal("expected authenticated session with network endpoint")
	}
	return session
}

func sgDesc(cluster string) string {
	return fmt.Sprintf("Security Group for Service LoadBalancer in cluster %s", cluster)
}

// Scenario: Pas d'endpoint "load-balancer" dans le catalogue → retour nil (LBs ignorés)
func TestDeleteLoadBalancers_NoLoadBalancerEndpoint_Skips(t *testing.T) {
	ks := newKeystoneServer(t)
	ks.catalog = catalogWith(
		serviceEntry("network",
			endpoint("public", "RegionOne", "http://network.example.com"),
		),
	)

	clouds := buildCloudsYAML(ks.URL, "v3applicationcredential")
	session, err := openstack.Authenticate(context.Background(), clouds, "openstack", "")
	if err != nil {
		t.Fatalf("unexpected authenticate error: %v", err)
	}

	err = session.DeleteLoadBalancers(context.Background(), logr.Discard(), "mycluster")
	if err != nil {
		t.Fatalf("expected nil when load-balancer endpoint is absent, got: %v", err)
	}
}

// ── Epic 4: Nettoyage des Security Groups ────────────────────────────────────

// ── US4.1: Identifier les Security Groups d'un cluster ───────────────────────

// Scenario: SG appartenant au cluster → inclus dans la suppression
// Scenario: SG d'un autre cluster → exclu
// Scenario: Description ne correspondant pas → exclu
func TestDeleteSecurityGroups_Filtering(t *testing.T) {
	tests := []struct {
		name         string
		description  string
		cluster      string
		shouldDelete bool
	}{
		{
			name:         "matching cluster",
			description:  sgDesc("mycluster"),
			cluster:      "mycluster",
			shouldDelete: true,
		},
		{
			name:         "different cluster",
			description:  sgDesc("othercluster"),
			cluster:      "mycluster",
			shouldDelete: false,
		},
		{
			name:         "wrong prefix",
			description:  "Group for Service LoadBalancer in cluster mycluster",
			cluster:      "mycluster",
			shouldDelete: false,
		},
		{
			name:         "unrelated description",
			description:  "Some other security group",
			cluster:      "mycluster",
			shouldDelete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newSGTestServer(t)
			sg := sgRecord{ID: "sg-001", Description: tt.description}
			srv.sgLists = [][]sgRecord{{sg}, {}}

			session := srv.authenticate(t)
			if err := session.DeleteSecurityGroups(context.Background(), logr.Discard(), tt.cluster); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			srv.mu.Lock()
			deleted := len(srv.deletedSGs) > 0
			srv.mu.Unlock()

			if deleted != tt.shouldDelete {
				t.Errorf("shouldDelete=%v but SG was deleted=%v", tt.shouldDelete, deleted)
			}
		})
	}
}

// ── US4.2: Supprimer les Security Groups ──────────────────────────────────────

// Scenario: Suppression réussie
func TestDeleteSecurityGroups_SuccessfulDeletion(t *testing.T) {
	srv := newSGTestServer(t)
	sgs := []sgRecord{
		{ID: "sg-001", Description: sgDesc("mycluster")},
		{ID: "sg-002", Description: sgDesc("mycluster")},
	}
	srv.sgLists = [][]sgRecord{sgs, {}}

	session := srv.authenticate(t)
	if err := session.DeleteSecurityGroups(context.Background(), logr.Discard(), "mycluster"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	srv.mu.Lock()
	deletedIDs := srv.deletedSGs
	srv.mu.Unlock()

	if len(deletedIDs) != 2 {
		t.Errorf("expected 2 SGs deleted, got %d: %v", len(deletedIDs), deletedIDs)
	}
	idSet := make(map[string]bool)
	for _, id := range deletedIDs {
		idSet[id] = true
	}
	for _, sg := range sgs {
		if !idSet[sg.ID] {
			t.Errorf("expected SG %s to be deleted", sg.ID)
		}
	}
}

// Scenario: SG encore utilisé (HTTP 409) → warning, continue, vérification déclenchée
func TestDeleteSecurityGroups_TransientError409_ContinuesAndVerifies(t *testing.T) {
	srv := newSGTestServer(t)
	sgs := []sgRecord{
		{ID: "sg-001", Description: sgDesc("mycluster")}, // returns HTTP 409
		{ID: "sg-002", Description: sgDesc("mycluster")}, // returns HTTP 204
	}
	srv.sgLists = [][]sgRecord{sgs, {}}
	srv.deleteStatus["sg-001"] = http.StatusConflict

	session := srv.authenticate(t)
	err := session.DeleteSecurityGroups(context.Background(), logr.Discard(), "mycluster")

	if err != nil {
		t.Fatalf("expected no error for transient HTTP 409, got: %v", err)
	}

	srv.mu.Lock()
	attempted := len(srv.deletedSGs)
	getCount := srv.sgGetCount
	srv.mu.Unlock()

	if attempted != 2 {
		t.Errorf("expected both SGs to be attempted, got %d DELETE calls", attempted)
	}
	// Verification GET must have been triggered (deleted=true even on transient error)
	if getCount < 2 {
		t.Errorf("expected at least 2 GET calls (list + verification), got %d", getCount)
	}
}

// Scenario: Erreur HTTP 500 → exception propagée
func TestDeleteSecurityGroups_HTTP500_PropagatesError(t *testing.T) {
	srv := newSGTestServer(t)
	srv.sgLists = [][]sgRecord{
		{{ID: "sg-server-error", Description: sgDesc("mycluster")}},
	}
	srv.deleteStatus["sg-server-error"] = http.StatusInternalServerError

	session := srv.authenticate(t)
	err := session.DeleteSecurityGroups(context.Background(), logr.Discard(), "mycluster")

	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

// Scenario: SGs toujours présents après suppression → erreur retournée
func TestDeleteSecurityGroups_StillPresentAfterDeletion_ReturnsError(t *testing.T) {
	srv := newSGTestServer(t)
	sg := sgRecord{ID: "sg-persistent", Description: sgDesc("mycluster")}
	srv.sgLists = [][]sgRecord{{sg}, {sg}}

	session := srv.authenticate(t)
	err := session.DeleteSecurityGroups(context.Background(), logr.Discard(), "mycluster")

	if err == nil {
		t.Fatal("expected error when SG persists after deletion")
	}
	if !strings.Contains(err.Error(), "mycluster") {
		t.Errorf("expected error to mention cluster name, got: %v", err)
	}
}

// Scenario: Aucun SG correspondant → pas de suppression, pas de vérification
func TestDeleteSecurityGroups_NothingToDelete_NoVerification(t *testing.T) {
	srv := newSGTestServer(t)
	srv.sgLists = [][]sgRecord{{}}

	session := srv.authenticate(t)
	if err := session.DeleteSecurityGroups(context.Background(), logr.Discard(), "mycluster"); err != nil {
		t.Fatalf("unexpected error with no SGs: %v", err)
	}

	srv.mu.Lock()
	deletedCount := len(srv.deletedSGs)
	getCount := srv.sgGetCount
	srv.mu.Unlock()

	if deletedCount != 0 {
		t.Errorf("expected no DELETE calls, got %d: %v", deletedCount, srv.deletedSGs)
	}
	if getCount != 1 {
		t.Errorf("expected exactly 1 GET call (no verification), got %d", getCount)
	}
}

// ── Cinder Volume mock server ─────────────────────────────────────────────────

type cinderVolumeRecord struct {
	ID       string            `json:"id"`
	Metadata map[string]string `json:"metadata"`
}

// cinderTestServer is a mock OpenStack server that handles Keystone auth +
// a Cinder-like volumes API. The catalog advertises the server's own URL as
// the "volumev3" endpoint (first type checked by cinderEndpoint).
type cinderTestServer struct {
	*httptest.Server
	mu             sync.Mutex
	volumeLists    [][]cinderVolumeRecord // sequence of list responses; last entry is reused
	volumeGetCount int
	deleteStatus   map[string]int
	deletedVolumes []string
}

func newCinderTestServer(t *testing.T) *cinderTestServer {
	t.Helper()
	srv := &cinderTestServer{
		deleteStatus: make(map[string]int),
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("X-Subject-Token", "test-cinder-token")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": map[string]any{"user": map[string]any{"id": "test-user"}},
		})
	})

	// Self-referential catalog: "volumev3" endpoint = this server.
	mux.HandleFunc("/v3/auth/catalog", func(w http.ResponseWriter, r *http.Request) {
		selfURL := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"catalog": []any{
				map[string]any{
					"type": "volumev3",
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

	// Cinder: list volumes (exact path — takes priority over /volumes/ subtree)
	mux.HandleFunc("/volumes/detail", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		srv.mu.Lock()
		srv.volumeGetCount++
		idx := srv.volumeGetCount - 1
		var list []cinderVolumeRecord
		if len(srv.volumeLists) > 0 {
			if idx < len(srv.volumeLists) {
				list = srv.volumeLists[idx]
			} else {
				list = srv.volumeLists[len(srv.volumeLists)-1]
			}
		}
		srv.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"volumes": list})
	})

	// Cinder: delete volume by ID (subtree pattern handles /volumes/{id})
	mux.HandleFunc("/volumes/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/volumes/")
		srv.mu.Lock()
		srv.deletedVolumes = append(srv.deletedVolumes, id)
		status, ok := srv.deleteStatus[id]
		if !ok {
			status = http.StatusNoContent
		}
		srv.mu.Unlock()
		w.WriteHeader(status)
	})

	srv.Server = httptest.NewServer(mux)
	t.Cleanup(srv.Server.Close)
	return srv
}

func (srv *cinderTestServer) authenticate(t *testing.T) *openstack.Session {
	t.Helper()
	cloudsYAML := fmt.Sprintf(`
clouds:
  openstack:
    auth_type: v3applicationcredential
    auth:
      auth_url: %s
      application_credential_id: test-id
      application_credential_secret: test-secret
    interface: public
    region_name: RegionOne
`, srv.URL)
	session, err := openstack.Authenticate(context.Background(), cloudsYAML, "openstack", "")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !session.IsAuthenticated() {
		t.Fatal("expected authenticated session with volumev3 endpoint")
	}
	return session
}

// ── Epic 5: Gestion des Volumes Cinder ───────────────────────────────────────

// ── US5.1: Identifier les volumes d'un cluster ───────────────────────────────

// Scenario: Volume du bon cluster sans keep → supprimé
// Scenario: Volume avec keep=true → conservé
// Scenario: Volume d'un autre cluster → exclu
// Scenario: Volume sans métadonnée CSI → exclu
func TestDeleteVolumes_Filtering(t *testing.T) {
	tests := []struct {
		name         string
		metadata     map[string]string
		cluster      string
		shouldDelete bool
	}{
		{
			name:         "matching cluster, no keep",
			metadata:     map[string]string{"cinder.csi.openstack.org/cluster": "mycluster"},
			cluster:      "mycluster",
			shouldDelete: true,
		},
		{
			name: "matching cluster, keep=true",
			metadata: map[string]string{
				"cinder.csi.openstack.org/cluster":    "mycluster",
				"janitor.capi.azimuth-cloud.com/keep": "true",
			},
			cluster:      "mycluster",
			shouldDelete: false,
		},
		{
			name:         "different cluster",
			metadata:     map[string]string{"cinder.csi.openstack.org/cluster": "othercluster"},
			cluster:      "mycluster",
			shouldDelete: false,
		},
		{
			name:         "no CSI metadata",
			metadata:     map[string]string{},
			cluster:      "mycluster",
			shouldDelete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newCinderTestServer(t)
			vol := cinderVolumeRecord{ID: "vol-001", Metadata: tt.metadata}
			srv.volumeLists = [][]cinderVolumeRecord{{vol}, {}}

			session := srv.authenticate(t)
			if err := session.DeleteVolumes(context.Background(), logr.Discard(), tt.cluster); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			srv.mu.Lock()
			deleted := len(srv.deletedVolumes) > 0
			srv.mu.Unlock()

			if deleted != tt.shouldDelete {
				t.Errorf("shouldDelete=%v but volume was deleted=%v", tt.shouldDelete, deleted)
			}
		})
	}
}

// Scenario: Suppression réussie de plusieurs volumes
func TestDeleteVolumes_SuccessfulDeletion(t *testing.T) {
	srv := newCinderTestServer(t)
	vols := []cinderVolumeRecord{
		{ID: "vol-001", Metadata: map[string]string{"cinder.csi.openstack.org/cluster": "mycluster"}},
		{ID: "vol-002", Metadata: map[string]string{"cinder.csi.openstack.org/cluster": "mycluster"}},
	}
	srv.volumeLists = [][]cinderVolumeRecord{vols, {}}

	session := srv.authenticate(t)
	if err := session.DeleteVolumes(context.Background(), logr.Discard(), "mycluster"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	srv.mu.Lock()
	deletedIDs := srv.deletedVolumes
	srv.mu.Unlock()

	if len(deletedIDs) != 2 {
		t.Errorf("expected 2 volumes deleted, got %d: %v", len(deletedIDs), deletedIDs)
	}
	idSet := make(map[string]bool)
	for _, id := range deletedIDs {
		idSet[id] = true
	}
	for _, vol := range vols {
		if !idSet[vol.ID] {
			t.Errorf("expected volume %s to be deleted", vol.ID)
		}
	}
}

// Scenario: Erreur HTTP 409 (transiente) → warning, continue, vérification déclenchée
func TestDeleteVolumes_TransientError409_ContinuesAndVerifies(t *testing.T) {
	srv := newCinderTestServer(t)
	vols := []cinderVolumeRecord{
		{ID: "vol-001", Metadata: map[string]string{"cinder.csi.openstack.org/cluster": "mycluster"}},
		{ID: "vol-002", Metadata: map[string]string{"cinder.csi.openstack.org/cluster": "mycluster"}},
	}
	srv.volumeLists = [][]cinderVolumeRecord{vols, {}}
	srv.deleteStatus["vol-001"] = http.StatusConflict

	session := srv.authenticate(t)
	err := session.DeleteVolumes(context.Background(), logr.Discard(), "mycluster")

	if err != nil {
		t.Fatalf("expected no error for transient HTTP 409, got: %v", err)
	}

	srv.mu.Lock()
	attempted := len(srv.deletedVolumes)
	getCount := srv.volumeGetCount
	srv.mu.Unlock()

	if attempted != 2 {
		t.Errorf("expected both volumes to be attempted, got %d DELETE calls", attempted)
	}
	if getCount < 2 {
		t.Errorf("expected at least 2 GET calls (list + verification), got %d", getCount)
	}
}

// Scenario: Erreur HTTP 500 → exception propagée
func TestDeleteVolumes_HTTP500_PropagatesError(t *testing.T) {
	srv := newCinderTestServer(t)
	srv.volumeLists = [][]cinderVolumeRecord{
		{{ID: "vol-server-error", Metadata: map[string]string{"cinder.csi.openstack.org/cluster": "mycluster"}}},
	}
	srv.deleteStatus["vol-server-error"] = http.StatusInternalServerError

	session := srv.authenticate(t)
	err := session.DeleteVolumes(context.Background(), logr.Discard(), "mycluster")

	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

// Scenario: Volume toujours présent après suppression → erreur retournée
func TestDeleteVolumes_StillPresentAfterDeletion_ReturnsError(t *testing.T) {
	srv := newCinderTestServer(t)
	vol := cinderVolumeRecord{
		ID:       "vol-persistent",
		Metadata: map[string]string{"cinder.csi.openstack.org/cluster": "mycluster"},
	}
	srv.volumeLists = [][]cinderVolumeRecord{{vol}, {vol}}

	session := srv.authenticate(t)
	err := session.DeleteVolumes(context.Background(), logr.Discard(), "mycluster")

	if err == nil {
		t.Fatal("expected error when volume persists after deletion")
	}
	if !strings.Contains(err.Error(), "mycluster") {
		t.Errorf("expected error to mention cluster name, got: %v", err)
	}
}

// Scenario: Aucun volume correspondant → pas de suppression, pas de vérification
func TestDeleteVolumes_NothingToDelete_NoVerification(t *testing.T) {
	srv := newCinderTestServer(t)
	srv.volumeLists = [][]cinderVolumeRecord{{}}

	session := srv.authenticate(t)
	if err := session.DeleteVolumes(context.Background(), logr.Discard(), "mycluster"); err != nil {
		t.Fatalf("unexpected error with no volumes: %v", err)
	}

	srv.mu.Lock()
	deletedCount := len(srv.deletedVolumes)
	getCount := srv.volumeGetCount
	srv.mu.Unlock()

	if deletedCount != 0 {
		t.Errorf("expected no DELETE calls, got %d: %v", deletedCount, srv.deletedVolumes)
	}
	if getCount != 1 {
		t.Errorf("expected exactly 1 GET call (no verification), got %d", getCount)
	}
}

// ── Cinder Snapshot mock server ───────────────────────────────────────────────

// snapshotTestServer is a mock OpenStack server handling Keystone auth +
// a Cinder-like snapshots API. Catalog advertises the server's own URL as
// the "volumev3" endpoint (same as volumes — same Cinder service).
type snapshotTestServer struct {
	*httptest.Server
	mu               sync.Mutex
	snapshotLists    [][]cinderVolumeRecord // reuse volumeItem shape (id + metadata)
	snapshotGetCount int
	deleteStatus     map[string]int
	deletedSnapshots []string
}

func newSnapshotTestServer(t *testing.T) *snapshotTestServer {
	t.Helper()
	srv := &snapshotTestServer{
		deleteStatus: make(map[string]int),
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("X-Subject-Token", "test-snapshot-token")
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
					"type": "volumev3",
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

	// Cinder: list snapshots (exact path — takes priority over /snapshots/ subtree)
	mux.HandleFunc("/snapshots/detail", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		srv.mu.Lock()
		srv.snapshotGetCount++
		idx := srv.snapshotGetCount - 1
		var list []cinderVolumeRecord
		if len(srv.snapshotLists) > 0 {
			if idx < len(srv.snapshotLists) {
				list = srv.snapshotLists[idx]
			} else {
				list = srv.snapshotLists[len(srv.snapshotLists)-1]
			}
		}
		srv.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"snapshots": list})
	})

	// Cinder: delete snapshot by ID (subtree pattern handles /snapshots/{id})
	mux.HandleFunc("/snapshots/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/snapshots/")
		srv.mu.Lock()
		srv.deletedSnapshots = append(srv.deletedSnapshots, id)
		status, ok := srv.deleteStatus[id]
		if !ok {
			status = http.StatusNoContent
		}
		srv.mu.Unlock()
		w.WriteHeader(status)
	})

	srv.Server = httptest.NewServer(mux)
	t.Cleanup(srv.Server.Close)
	return srv
}

func (srv *snapshotTestServer) authenticate(t *testing.T) *openstack.Session {
	t.Helper()
	cloudsYAML := fmt.Sprintf(`
clouds:
  openstack:
    auth_type: v3applicationcredential
    auth:
      auth_url: %s
      application_credential_id: test-id
      application_credential_secret: test-secret
    interface: public
    region_name: RegionOne
`, srv.URL)
	session, err := openstack.Authenticate(context.Background(), cloudsYAML, "openstack", "")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !session.IsAuthenticated() {
		t.Fatal("expected authenticated session with volumev3 endpoint")
	}
	return session
}

// ── Epic 6: Gestion des Snapshots Cinder ─────────────────────────────────────

// ── US6.1: Identifier et supprimer les snapshots d'un cluster ────────────────

// Scenario: Snapshot du bon cluster → supprimé
// Scenario: Snapshot d'un autre cluster → exclu
func TestDeleteSnapshots_Filtering(t *testing.T) {
	tests := []struct {
		name         string
		metadata     map[string]string
		cluster      string
		shouldDelete bool
	}{
		{
			name:         "matching cluster",
			metadata:     map[string]string{"cinder.csi.openstack.org/cluster": "mycluster"},
			cluster:      "mycluster",
			shouldDelete: true,
		},
		{
			name:         "different cluster",
			metadata:     map[string]string{"cinder.csi.openstack.org/cluster": "othercluster"},
			cluster:      "mycluster",
			shouldDelete: false,
		},
		{
			name:         "no CSI metadata",
			metadata:     map[string]string{},
			cluster:      "mycluster",
			shouldDelete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newSnapshotTestServer(t)
			snap := cinderVolumeRecord{ID: "snap-001", Metadata: tt.metadata}
			srv.snapshotLists = [][]cinderVolumeRecord{{snap}, {}}

			session := srv.authenticate(t)
			if err := session.DeleteSnapshots(context.Background(), logr.Discard(), tt.cluster); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			srv.mu.Lock()
			deleted := len(srv.deletedSnapshots) > 0
			srv.mu.Unlock()

			if deleted != tt.shouldDelete {
				t.Errorf("shouldDelete=%v but snapshot was deleted=%v", tt.shouldDelete, deleted)
			}
		})
	}
}

// Scenario: Suppression réussie de plusieurs snapshots
func TestDeleteSnapshots_SuccessfulDeletion(t *testing.T) {
	srv := newSnapshotTestServer(t)
	snaps := []cinderVolumeRecord{
		{ID: "snap-001", Metadata: map[string]string{"cinder.csi.openstack.org/cluster": "mycluster"}},
		{ID: "snap-002", Metadata: map[string]string{"cinder.csi.openstack.org/cluster": "mycluster"}},
	}
	srv.snapshotLists = [][]cinderVolumeRecord{snaps, {}}

	session := srv.authenticate(t)
	if err := session.DeleteSnapshots(context.Background(), logr.Discard(), "mycluster"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	srv.mu.Lock()
	deletedIDs := srv.deletedSnapshots
	srv.mu.Unlock()

	if len(deletedIDs) != 2 {
		t.Errorf("expected 2 snapshots deleted, got %d: %v", len(deletedIDs), deletedIDs)
	}
	idSet := make(map[string]bool)
	for _, id := range deletedIDs {
		idSet[id] = true
	}
	for _, snap := range snaps {
		if !idSet[snap.ID] {
			t.Errorf("expected snapshot %s to be deleted", snap.ID)
		}
	}
}

// Scenario: Erreur HTTP 409 (transiente) → warning, continue, vérification déclenchée
func TestDeleteSnapshots_TransientError409_ContinuesAndVerifies(t *testing.T) {
	srv := newSnapshotTestServer(t)
	snaps := []cinderVolumeRecord{
		{ID: "snap-001", Metadata: map[string]string{"cinder.csi.openstack.org/cluster": "mycluster"}},
		{ID: "snap-002", Metadata: map[string]string{"cinder.csi.openstack.org/cluster": "mycluster"}},
	}
	srv.snapshotLists = [][]cinderVolumeRecord{snaps, {}}
	srv.deleteStatus["snap-001"] = http.StatusConflict

	session := srv.authenticate(t)
	err := session.DeleteSnapshots(context.Background(), logr.Discard(), "mycluster")

	if err != nil {
		t.Fatalf("expected no error for transient HTTP 409, got: %v", err)
	}

	srv.mu.Lock()
	attempted := len(srv.deletedSnapshots)
	getCount := srv.snapshotGetCount
	srv.mu.Unlock()

	if attempted != 2 {
		t.Errorf("expected both snapshots to be attempted, got %d DELETE calls", attempted)
	}
	if getCount < 2 {
		t.Errorf("expected at least 2 GET calls (list + verification), got %d", getCount)
	}
}

// Scenario: Erreur HTTP 500 → exception propagée
func TestDeleteSnapshots_HTTP500_PropagatesError(t *testing.T) {
	srv := newSnapshotTestServer(t)
	srv.snapshotLists = [][]cinderVolumeRecord{
		{{ID: "snap-server-error", Metadata: map[string]string{"cinder.csi.openstack.org/cluster": "mycluster"}}},
	}
	srv.deleteStatus["snap-server-error"] = http.StatusInternalServerError

	session := srv.authenticate(t)
	err := session.DeleteSnapshots(context.Background(), logr.Discard(), "mycluster")

	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

// Scenario: Snapshot toujours présent après suppression → erreur retournée
func TestDeleteSnapshots_StillPresentAfterDeletion_ReturnsError(t *testing.T) {
	srv := newSnapshotTestServer(t)
	snap := cinderVolumeRecord{
		ID:       "snap-persistent",
		Metadata: map[string]string{"cinder.csi.openstack.org/cluster": "mycluster"},
	}
	srv.snapshotLists = [][]cinderVolumeRecord{{snap}, {snap}}

	session := srv.authenticate(t)
	err := session.DeleteSnapshots(context.Background(), logr.Discard(), "mycluster")

	if err == nil {
		t.Fatal("expected error when snapshot persists after deletion")
	}
	if !strings.Contains(err.Error(), "mycluster") {
		t.Errorf("expected error to mention cluster name, got: %v", err)
	}
}

// Scenario: Aucun snapshot correspondant → pas de suppression, pas de vérification
func TestDeleteSnapshots_NothingToDelete_NoVerification(t *testing.T) {
	srv := newSnapshotTestServer(t)
	srv.snapshotLists = [][]cinderVolumeRecord{{}}

	session := srv.authenticate(t)
	if err := session.DeleteSnapshots(context.Background(), logr.Discard(), "mycluster"); err != nil {
		t.Fatalf("unexpected error with no snapshots: %v", err)
	}

	srv.mu.Lock()
	deletedCount := len(srv.deletedSnapshots)
	getCount := srv.snapshotGetCount
	srv.mu.Unlock()

	if deletedCount != 0 {
		t.Errorf("expected no DELETE calls, got %d: %v", deletedCount, srv.deletedSnapshots)
	}
	if getCount != 1 {
		t.Errorf("expected exactly 1 GET call (no verification), got %d", getCount)
	}
}
