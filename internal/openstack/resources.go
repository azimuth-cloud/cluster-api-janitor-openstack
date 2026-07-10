package openstack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
)

// DeleteFloatingIPs removes FIPs whose description matches the cluster.
// Expected: "Floating IP for Kubernetes external service from cluster <name>"
func (s *Session) DeleteFloatingIPs(ctx context.Context, logger logr.Logger, cluster string) error {
	networkURL, err := s.endpointFor("network")
	if err != nil {
		return err
	}
	prefix := "Floating IP for Kubernetes"
	suffix := "from cluster " + cluster

	type fip struct {
		ID          string `json:"id"`
		Description string `json:"description"`
	}
	list, err := listPages[fip](ctx, s, networkURL+"/v2.0/floatingips", "floatingips")
	if err != nil {
		return err
	}
	deleted := false
	for _, f := range list {
		if strings.HasPrefix(f.Description, prefix) && strings.HasSuffix(f.Description, suffix) {
			// Mark found before attempting deletion so verification always runs,
			// even when the delete returns a transient error.
			deleted = true
			logger.Info("deleting floating IP", "id", f.ID)
			if err := s.doDelete(ctx, networkURL+"/v2.0/floatingips/"+f.ID); err != nil {
				if isTransient(err) {
					logger.Info("transient error deleting floating IP, will verify", "id", f.ID, "error", err)
				} else {
					return err
				}
			}
		}
	}
	if deleted {
		listFIPs := func() ([]fip, error) {
			return listPages[fip](ctx, s, networkURL+"/v2.0/floatingips", "floatingips")
		}
		matchFIP := func(f fip) bool {
			return strings.HasPrefix(f.Description, prefix) && strings.HasSuffix(f.Description, suffix)
		}
		if err := waitForDeletion(ctx, s, logger, listFIPs, matchFIP, "floating IPs for cluster "+cluster); err != nil {
			return err
		}
	}
	logger.Info("deleted floating IPs for LoadBalancer services")
	return nil
}

// DeleteLoadBalancers removes Octavia LBs whose name starts with kube_service_<cluster>_
// or follows the Azimuth naming convention.
func (s *Session) DeleteLoadBalancers(ctx context.Context, logger logr.Logger, cluster string) error {
	lbURL, err := s.endpointFor("load-balancer")
	if err != nil {
		logger.Info("load-balancer service not found in catalog, skipping LB cleanup")
		return nil
	}

	type lb struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	list, err := listPages[lb](ctx, s, lbURL+"/v2/lbaas/loadbalancers", "loadbalancers")
	if err != nil {
		logger.Error(err, "failed to list load balancers, some may remain")
		return nil
	}
	kubePrefix := "kube_service_" + cluster + "_"
	deleted := false
	for _, l := range list {
		if strings.HasPrefix(l.Name, kubePrefix) {
			deleted = true
			logger.Info("deleting load balancer", "id", l.ID, "name", l.Name)
			target := lbURL + "/v2/lbaas/loadbalancers/" + l.ID + "?cascade=true"
			if err := s.doDelete(ctx, target); err != nil {
				if isTransient(err) {
					logger.Info("transient error deleting load balancer, will verify", "id", l.ID, "error", err)
				} else {
					return err
				}
			}
		}
	}
	if deleted {
		listLBs := func() ([]lb, error) {
			return listPages[lb](ctx, s, lbURL+"/v2/lbaas/loadbalancers", "loadbalancers")
		}
		matchLB := func(l lb) bool {
			return strings.HasPrefix(l.Name, kubePrefix)
		}
		if err := waitForDeletion(ctx, s, logger, listLBs, matchLB, "load balancers for cluster "+cluster); err != nil {
			logger.Error(err, "failed to verify LB deletion after polling")
			return err
		}
	}
	logger.Info("deleted load balancers for LoadBalancer services")
	return nil
}

// DeleteSecurityGroups removes SGs whose description matches the cluster LB pattern.
// Expected: "Security Group for Service LoadBalancer in cluster <name>"
func (s *Session) DeleteSecurityGroups(ctx context.Context, logger logr.Logger, cluster string) error {
	networkURL, err := s.endpointFor("network")
	if err != nil {
		return err
	}
	sgSuffix := "Service LoadBalancer in cluster " + cluster

	type sg struct {
		ID          string `json:"id"`
		Description string `json:"description"`
	}
	list, err := listPages[sg](ctx, s, networkURL+"/v2.0/security-groups", "security_groups")
	if err != nil {
		return err
	}
	deleted := false
	for _, g := range list {
		if strings.HasPrefix(g.Description, "Security Group for") && strings.HasSuffix(g.Description, sgSuffix) {
			deleted = true
			logger.Info("deleting security group", "id", g.ID)
			if err := s.doDelete(ctx, networkURL+"/v2.0/security-groups/"+g.ID); err != nil {
				if isTransient(err) {
					logger.Info("transient error deleting security group, will verify", "id", g.ID, "error", err)
				} else {
					return err
				}
			}
		}
	}
	if deleted {
		listSGs := func() ([]sg, error) {
			return listPages[sg](ctx, s, networkURL+"/v2.0/security-groups", "security_groups")
		}
		matchSG := func(g sg) bool {
			return strings.HasPrefix(g.Description, "Security Group for") && strings.HasSuffix(g.Description, sgSuffix)
		}
		if err := waitForDeletion(ctx, s, logger, listSGs, matchSG, "security groups for cluster "+cluster); err != nil {
			return err
		}
	}
	logger.Info("deleted security groups for LoadBalancer services")
	return nil
}

// volumeItem represents a Cinder volume or snapshot with its metadata.
type volumeItem struct {
	ID       string            `json:"id"`
	Metadata map[string]string `json:"metadata"`
}

// DeleteSnapshots removes Cinder snapshots tagged with the cluster CSI metadata.
func (s *Session) DeleteSnapshots(ctx context.Context, logger logr.Logger, cluster string) error {
	cinderURL, err := s.cinderEndpoint()
	if err != nil {
		return err
	}
	list, err := s.listVolumeItems(ctx, cinderURL+"/snapshots/detail", "snapshots")
	if err != nil {
		return err
	}
	deleted := false
	for _, snap := range list {
		if snap.Metadata["cinder.csi.openstack.org/cluster"] == cluster {
			deleted = true
			logger.Info("deleting snapshot", "id", snap.ID)
			if err := s.doDelete(ctx, cinderURL+"/snapshots/"+snap.ID); err != nil {
				if isTransient(err) {
					logger.Info("transient error deleting snapshot, will verify", "id", snap.ID, "error", err)
				} else {
					return err
				}
			}
		}
	}
	if deleted {
		listSnaps := func() ([]volumeItem, error) {
			return s.listVolumeItems(ctx, cinderURL+"/snapshots/detail", "snapshots")
		}
		matchSnap := func(snap volumeItem) bool {
			return snap.Metadata["cinder.csi.openstack.org/cluster"] == cluster
		}
		if err := waitForDeletion(ctx, s, logger, listSnaps, matchSnap, "snapshots for cluster "+cluster); err != nil {
			return err
		}
	}
	logger.Info("deleted snapshots for persistent volume claims")
	return nil
}

// DeleteVolumes removes Cinder volumes tagged with the cluster CSI metadata,
// unless the user has set the keep property to "true".
func (s *Session) DeleteVolumes(ctx context.Context, logger logr.Logger, cluster string) error {
	cinderURL, err := s.cinderEndpoint()
	if err != nil {
		return err
	}
	list, err := s.listVolumeItems(ctx, cinderURL+"/volumes/detail", "volumes")
	if err != nil {
		return err
	}
	deleted := false
	for _, vol := range list {
		if vol.Metadata["cinder.csi.openstack.org/cluster"] != cluster {
			continue
		}
		if vol.Metadata[KeepProperty] == "true" {
			continue
		}
		deleted = true
		logger.Info("deleting volume", "id", vol.ID)
		if err := s.doDelete(ctx, cinderURL+"/volumes/"+vol.ID); err != nil {
			if isTransient(err) {
				logger.Info("transient error deleting volume, will verify", "id", vol.ID, "error", err)
			} else {
				return err
			}
		}
	}
	if deleted {
		listVols := func() ([]volumeItem, error) {
			return s.listVolumeItems(ctx, cinderURL+"/volumes/detail", "volumes")
		}
		matchVol := func(vol volumeItem) bool {
			return vol.Metadata["cinder.csi.openstack.org/cluster"] == cluster &&
				vol.Metadata[KeepProperty] != "true"
		}
		if err := waitForDeletion(ctx, s, logger, listVols, matchVol, "volumes for cluster "+cluster); err != nil {
			return err
		}
	}
	logger.Info("deleted volumes for persistent volume claims")
	return nil
}

// DeleteAppCredential removes the OpenStack application credential for the cluster.
func (s *Session) DeleteAppCredential(ctx context.Context, logger logr.Logger, cloudsYAML, cloudName string) error {
	identityURL, err := s.endpointFor("identity")
	if err != nil {
		return err
	}
	appcredID, err := AppCredentialID(cloudsYAML, cloudName)
	if err != nil {
		return err
	}
	if appcredID == "" {
		// Password (v3password) auth has no application credential to delete.
		logger.Info("no application credential in use, skipping deletion")
		return nil
	}
	target := strings.TrimRight(identityURL, "/") + "/v3/users/" + s.userID + "/application_credentials/" + appcredID
	req, err := newDeleteRequest(ctx, target, s.token)
	if err != nil {
		return err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusNotFound:
		logger.Info("deleted application credential for cluster")
		return nil
	case http.StatusForbidden:
		logger.Info("unable to delete application credential (restricted), skipping")
		return nil
	default:
		return fmt.Errorf("deleting application credential: HTTP %d", resp.StatusCode)
	}
}

func (s *Session) cinderEndpoint() (string, error) {
	return s.endpointFor("volumev3", "block-storage", "volume")
}

func (s *Session) listVolumeItems(ctx context.Context, endpoint, key string) ([]volumeItem, error) {
	body, err := s.doGet(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	var items []volumeItem
	if err := json.Unmarshal(raw[key], &items); err != nil {
		return nil, err
	}
	return items, nil
}

func newDeleteRequest(ctx context.Context, target, token string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	return req, nil
}

// waitForDeletion polls a list function until no items match the predicate,
// or the maximum number of attempts is exceeded. This avoids failing
// immediately when OpenStack has accepted a DELETE but the resource has
// not yet been removed from list results.
func waitForDeletion[T any](ctx context.Context, s *Session, logger logr.Logger, listFunc func() ([]T, error), matchFunc func(T) bool, desc string) error {
	const (
		maxPollAttempts = 6
		pollInterval    = 5 * time.Second
	)
	for attempt := 0; attempt < maxPollAttempts; attempt++ {
		s.sleep(pollInterval)
		items, err := listFunc()
		if err != nil {
			return err
		}
		remaining := 0
		for _, item := range items {
			if matchFunc(item) {
				remaining++
			}
		}
		if remaining == 0 {
			return nil
		}
		logger.Info(desc+" still present, retrying", "remaining", remaining, "attempt", attempt+1, "maxAttempts", maxPollAttempts)
	}
	return fmt.Errorf("%s still present", desc)
}

// listPages fetches all pages of a paginated OpenStack list endpoint and
// decodes items into T using the given JSON key.
func listPages[T any](ctx context.Context, s *Session, endpoint, key string) ([]T, error) {
	var results []T
	next := endpoint
	for next != "" {
		body, err := s.doGet(ctx, next)
		if err != nil {
			return nil, err
		}
		var page map[string]json.RawMessage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}
		var items []T
		if err := json.Unmarshal(page[key], &items); err != nil {
			return nil, err
		}
		results = append(results, items...)
		next = nextPageURL(body, key)
	}
	return results, nil
}

func nextPageURL(body []byte, key string) string {
	linksKey := key + "_links"
	var page map[string]json.RawMessage
	if err := json.Unmarshal(body, &page); err != nil {
		return ""
	}
	raw, ok := page[linksKey]
	if !ok {
		return ""
	}
	var links []struct {
		Rel  string `json:"rel"`
		Href string `json:"href"`
	}
	if err := json.Unmarshal(raw, &links); err != nil {
		return ""
	}
	for _, l := range links {
		if l.Rel == "next" {
			u, err := url.Parse(l.Href)
			if err != nil {
				return l.Href
			}
			// OpenStack sometimes returns http where https is required.
			u.Scheme = "https"
			return u.String()
		}
	}
	return ""
}
