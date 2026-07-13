package controller_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/azimuth-cloud/cluster-api-janitor-openstack/internal/controller"
	"github.com/azimuth-cloud/cluster-api-janitor-openstack/internal/openstack"
)

func newObsReconciler(
	reg *prometheus.Registry,
	purgeFunc func(context.Context, openstack.PurgeOptions) error,
	objs ...client.Object,
) (*controller.OpenStackClusterReconciler, *record.FakeRecorder) {
	r, _ := newReconciler(purgeFunc, objs...)
	r.Metrics = controller.NewMetrics(reg)
	rec := record.NewFakeRecorder(10)
	r.Recorder = rec
	return r, rec
}

// ── US11.1: Prometheus Metrics ────────────────────────────────────────────

// Scenario: successful cleanup → capi_janitor_cleanups_total{result="success"} += 1
func TestMetrics_IncrementsSuccess_OnCleanup(t *testing.T) {
	cluster := newCluster("c", "default", withFinalizer, withDeletionTimestamp)
	secret := newSecret("cloud-credentials", "default")

	reg := prometheus.NewRegistry()
	r, _ := newObsReconciler(reg,
		func(_ context.Context, _ openstack.PurgeOptions) error { return nil },
		cluster, secret,
	)

	if _, err := r.Reconcile(context.Background(), reconcileRequest("c", "default")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := testutil.ToFloat64(r.Metrics.CleanupsTotal.WithLabelValues("success")); got != 1 {
		t.Errorf("expected cleanupsTotal{result=success}=1, got %v", got)
	}
}

// Scenario: failed purge → capi_janitor_cleanups_total{result="failure"} += 1
func TestMetrics_IncrementsFailure_OnPurgeError(t *testing.T) {
	cluster := newCluster("c", "default", withFinalizer, withDeletionTimestamp)
	secret := newSecret("cloud-credentials", "default")

	reg := prometheus.NewRegistry()
	r, _ := newObsReconciler(reg,
		func(_ context.Context, _ openstack.PurgeOptions) error { return errors.New("purge failed") },
		cluster, secret,
	)

	if _, err := r.Reconcile(context.Background(), reconcileRequest("c", "default")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := testutil.ToFloat64(r.Metrics.CleanupsTotal.WithLabelValues("failure")); got != 1 {
		t.Errorf("expected cleanupsTotal{result=failure}=1, got %v", got)
	}
}

// ── US11.2: Kubernetes Events ───────────────────────────────────────────────

// Scenario: successful cleanup → Normal "CleanupSucceeded" event
func TestEvents_EmitsNormal_OnCleanupSuccess(t *testing.T) {
	cluster := newCluster("c", "default", withFinalizer, withDeletionTimestamp)
	secret := newSecret("cloud-credentials", "default")

	reg := prometheus.NewRegistry()
	r, rec := newObsReconciler(reg,
		func(_ context.Context, _ openstack.PurgeOptions) error { return nil },
		cluster, secret,
	)

	if _, err := r.Reconcile(context.Background(), reconcileRequest("c", "default")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case event := <-rec.Events:
		if !strings.Contains(event, "Normal") || !strings.Contains(event, "CleanupSucceeded") {
			t.Errorf("expected Normal/CleanupSucceeded event, got: %q", event)
		}
	default:
		t.Error("no event was recorded")
	}
}

// Scenario: failed purge → Warning "CleanupFailed" event
func TestEvents_EmitsWarning_OnPurgeFailure(t *testing.T) {
	cluster := newCluster("c", "default", withFinalizer, withDeletionTimestamp)
	secret := newSecret("cloud-credentials", "default")

	reg := prometheus.NewRegistry()
	r, rec := newObsReconciler(reg,
		func(_ context.Context, _ openstack.PurgeOptions) error { return errors.New("purge failed") },
		cluster, secret,
	)

	if _, err := r.Reconcile(context.Background(), reconcileRequest("c", "default")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case event := <-rec.Events:
		if !strings.Contains(event, "Warning") || !strings.Contains(event, "CleanupFailed") {
			t.Errorf("expected Warning/CleanupFailed event, got: %q", event)
		}
	default:
		t.Error("no event was recorded")
	}
}
