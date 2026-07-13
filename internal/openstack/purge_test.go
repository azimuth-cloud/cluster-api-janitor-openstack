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

// purgeTestServer is a single mock OpenStack server that advertises every
// service PurgeResources touches (network, load-balancer, volumev3, identity)
// from one self-referential catalog, so PurgeResources can run end-to-end
// against a single httptest.Server.
type purgeTestServer struct {
	*httptest.Server
	mu sync.Mutex

	tokenStatus int // default http.StatusCreated; set 404 to simulate a deleted appcred

	fipList  []fipRecord
	lbList   []lbRecord
	sgList   []sgRecord
	volList  []cinderVolumeRecord
	snapList []cinderVolumeRecord

	fipListStatus int // non-zero overrides the GET /v2.0/floatingips response status
	volListStatus int // non-zero overrides the GET /volumes/detail response status

	fipListCalls, lbListCalls, sgListCalls, volListCalls, snapListCalls, appcredDeleteCalls int
	deletedAppcredID                                                                        string
}

func newPurgeTestServer(t *testing.T) *purgeTestServer {
	t.Helper()
	srv := &purgeTestServer{tokenStatus: http.StatusCreated}
	mux := http.NewServeMux()

	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		srv.mu.Lock()
		status := srv.tokenStatus
		srv.mu.Unlock()
		if status >= 400 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("X-Subject-Token", "purge-token")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": map[string]any{"user": map[string]any{"id": "purge-user"}},
		})
	})

	mux.HandleFunc("/v3/auth/catalog", func(w http.ResponseWriter, r *http.Request) {
		selfURL := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"catalog": []any{
				map[string]any{"type": "network", "endpoints": []any{
					map[string]any{"interface": "public", "region_id": "RegionOne", "url": selfURL},
				}},
				map[string]any{"type": "load-balancer", "endpoints": []any{
					map[string]any{"interface": "public", "region_id": "RegionOne", "url": selfURL},
				}},
				map[string]any{"type": "volumev3", "endpoints": []any{
					map[string]any{"interface": "public", "region_id": "RegionOne", "url": selfURL},
				}},
				map[string]any{"type": "identity", "endpoints": []any{
					map[string]any{"interface": "public", "region_id": "RegionOne", "url": selfURL},
				}},
			},
		})
	})

	mux.HandleFunc("/v2.0/floatingips", func(w http.ResponseWriter, r *http.Request) {
		srv.mu.Lock()
		srv.fipListCalls++
		status := srv.fipListStatus
		list := srv.fipList
		srv.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"floatingips": list})
	})
	mux.HandleFunc("/v2.0/floatingips/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/v2/lbaas/loadbalancers", func(w http.ResponseWriter, r *http.Request) {
		srv.mu.Lock()
		srv.lbListCalls++
		list := srv.lbList
		srv.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"loadbalancers": list})
	})
	mux.HandleFunc("/v2/lbaas/loadbalancers/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/v2.0/security-groups", func(w http.ResponseWriter, r *http.Request) {
		srv.mu.Lock()
		srv.sgListCalls++
		list := srv.sgList
		srv.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"security_groups": list})
	})
	mux.HandleFunc("/v2.0/security-groups/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/snapshots/detail", func(w http.ResponseWriter, r *http.Request) {
		srv.mu.Lock()
		srv.snapListCalls++
		list := srv.snapList
		srv.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"snapshots": list})
	})
	mux.HandleFunc("/snapshots/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/volumes/detail", func(w http.ResponseWriter, r *http.Request) {
		srv.mu.Lock()
		srv.volListCalls++
		status := srv.volListStatus
		list := srv.volList
		srv.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"volumes": list})
	})
	mux.HandleFunc("/volumes/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/v3/users/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/application_credentials/")
		srv.mu.Lock()
		srv.appcredDeleteCalls++
		if len(parts) == 2 {
			srv.deletedAppcredID = parts[1]
		}
		srv.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	srv.Server = httptest.NewServer(mux)
	t.Cleanup(srv.Server.Close)
	return srv
}

func buildPurgeCloudsYAML(authURL string) string {
	return fmt.Sprintf(`
clouds:
  openstack:
    auth_type: v3applicationcredential
    auth:
      auth_url: %s
      application_credential_id: purge-appcred-id
      application_credential_secret: purge-secret
    interface: public
    region_name: RegionOne
`, authURL)
}

func TestPurgeResources_AuthenticateError_Propagates(t *testing.T) {
	err := openstack.PurgeResources(context.Background(), openstack.PurgeOptions{
		CloudsYAML: "not: valid: yaml: :",
		CloudName:  "openstack",
		Logger:     logr.Discard(),
	})
	if err == nil {
		t.Fatal("expected error from Authenticate, got nil")
	}
}

func TestPurgeResources_Unauthenticated_IncludeAppcredTrue_ReturnsNilAndSkips(t *testing.T) {
	srv := newPurgeTestServer(t)
	srv.tokenStatus = http.StatusNotFound

	err := openstack.PurgeResources(context.Background(), openstack.PurgeOptions{
		CloudsYAML:     buildPurgeCloudsYAML(srv.URL),
		CloudName:      "openstack",
		IncludeAppcred: true,
		Logger:         logr.Discard(),
	})
	if err != nil {
		t.Fatalf("expected nil error when appcred already deleted, got: %v", err)
	}
}

func TestPurgeResources_Unauthenticated_IncludeAppcredFalse_ReturnsAuthenticationError(t *testing.T) {
	srv := newPurgeTestServer(t)
	srv.tokenStatus = http.StatusNotFound

	err := openstack.PurgeResources(context.Background(), openstack.PurgeOptions{
		CloudsYAML:     buildPurgeCloudsYAML(srv.URL),
		CloudName:      "openstack",
		IncludeAppcred: false,
		Logger:         logr.Discard(),
	})
	var target *openstack.AuthenticationError
	if !errorAs(err, &target) {
		t.Fatalf("expected *AuthenticationError, got %T: %v", err, err)
	}
}

func TestPurgeResources_DeleteFloatingIPsError_ShortCircuits(t *testing.T) {
	srv := newPurgeTestServer(t)
	srv.fipListStatus = http.StatusInternalServerError

	err := openstack.PurgeResources(context.Background(), openstack.PurgeOptions{
		CloudsYAML:     buildPurgeCloudsYAML(srv.URL),
		CloudName:      "openstack",
		IncludeVolumes: true,
		IncludeAppcred: true,
		Logger:         logr.Discard(),
	})
	if err == nil {
		t.Fatal("expected error from DeleteFloatingIPs, got nil")
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.lbListCalls != 0 || srv.sgListCalls != 0 || srv.volListCalls != 0 || srv.snapListCalls != 0 || srv.appcredDeleteCalls != 0 {
		t.Errorf("expected no further resource calls after FIP error, got lb=%d sg=%d vol=%d snap=%d appcred=%d",
			srv.lbListCalls, srv.sgListCalls, srv.volListCalls, srv.snapListCalls, srv.appcredDeleteCalls)
	}
}

func TestPurgeResources_DeleteVolumesError_ShortCircuits(t *testing.T) {
	srv := newPurgeTestServer(t)
	srv.volListStatus = http.StatusInternalServerError

	err := openstack.PurgeResources(context.Background(), openstack.PurgeOptions{
		CloudsYAML:     buildPurgeCloudsYAML(srv.URL),
		CloudName:      "openstack",
		IncludeVolumes: true,
		IncludeAppcred: true,
		Logger:         logr.Discard(),
	})
	if err == nil {
		t.Fatal("expected error from DeleteVolumes, got nil")
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.appcredDeleteCalls != 0 {
		t.Errorf("expected DeleteAppCredential not to be called after DeleteVolumes error, got %d calls", srv.appcredDeleteCalls)
	}
}

func TestPurgeResources_IncludeVolumesFalse_SkipsSnapshotsAndVolumes(t *testing.T) {
	srv := newPurgeTestServer(t)

	err := openstack.PurgeResources(context.Background(), openstack.PurgeOptions{
		CloudsYAML:     buildPurgeCloudsYAML(srv.URL),
		CloudName:      "openstack",
		IncludeVolumes: false,
		IncludeAppcred: false,
		Logger:         logr.Discard(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.volListCalls != 0 || srv.snapListCalls != 0 {
		t.Errorf("expected no volume/snapshot list calls when IncludeVolumes is false, got vol=%d snap=%d", srv.volListCalls, srv.snapListCalls)
	}
}

func TestPurgeResources_IncludeAppcredTrue_CallsDeleteAppCredential(t *testing.T) {
	srv := newPurgeTestServer(t)

	err := openstack.PurgeResources(context.Background(), openstack.PurgeOptions{
		CloudsYAML:     buildPurgeCloudsYAML(srv.URL),
		CloudName:      "openstack",
		IncludeVolumes: false,
		IncludeAppcred: true,
		Logger:         logr.Discard(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.deletedAppcredID != "purge-appcred-id" {
		t.Errorf("expected appcred %q to be deleted, got %q", "purge-appcred-id", srv.deletedAppcredID)
	}
}

func TestPurgeResources_FullSuccess_ReturnsNil(t *testing.T) {
	srv := newPurgeTestServer(t)

	err := openstack.PurgeResources(context.Background(), openstack.PurgeOptions{
		CloudsYAML:     buildPurgeCloudsYAML(srv.URL),
		CloudName:      "openstack",
		IncludeVolumes: true,
		IncludeAppcred: false,
		Logger:         logr.Discard(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
