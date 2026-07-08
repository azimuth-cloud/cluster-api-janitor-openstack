package controller_test

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	infrav1 "sigs.k8s.io/cluster-api-provider-openstack/api/v1beta1"

	"github.com/azimuth-cloud/cluster-api-janitor-openstack/internal/controller"
	"github.com/azimuth-cloud/cluster-api-janitor-openstack/internal/openstack"
)

// ── US9.1: Configuration via environment variables ────────────────────────

// Scenario: CAPI_JANITOR_DEFAULT_VOLUMES_POLICY not set → "delete"
func TestDefaultVolumesFromEnv_DefaultsToDelete(t *testing.T) {
	t.Setenv("CAPI_JANITOR_DEFAULT_VOLUMES_POLICY", "")
	if got := controller.DefaultVolumesFromEnv(); got != controller.PolicyDelete {
		t.Errorf("expected %q, got %q", controller.PolicyDelete, got)
	}
}

// Scenario: CAPI_JANITOR_DEFAULT_VOLUMES_POLICY = "keep" → "keep"
func TestDefaultVolumesFromEnv_ReadsKeep(t *testing.T) {
	t.Setenv("CAPI_JANITOR_DEFAULT_VOLUMES_POLICY", "keep")
	if got := controller.DefaultVolumesFromEnv(); got != "keep" {
		t.Errorf("expected %q, got %q", "keep", got)
	}
}

// Scenario: CAPI_JANITOR_RETRY_DEFAULT_DELAY not set → 60s (default)
func TestRetryDelayFromEnv_DefaultsTo60(t *testing.T) {
	t.Setenv("CAPI_JANITOR_RETRY_DEFAULT_DELAY", "")
	if got := controller.RetryDelayFromEnv(); got != 60 {
		t.Errorf("expected 60, got %d", got)
	}
}

// Scenario: CAPI_JANITOR_RETRY_DEFAULT_DELAY = "120" → 120
func TestRetryDelayFromEnv_ReadsConfiguredDelay(t *testing.T) {
	t.Setenv("CAPI_JANITOR_RETRY_DEFAULT_DELAY", "120")
	if got := controller.RetryDelayFromEnv(); got != 120 {
		t.Errorf("expected 120, got %d", got)
	}
}

// Scenario: CAPI_JANITOR_RETRY_DEFAULT_DELAY invalide → 60 (fallback)
func TestRetryDelayFromEnv_InvalidValue_FallsBackToDefault(t *testing.T) {
	t.Setenv("CAPI_JANITOR_RETRY_DEFAULT_DELAY", "not-a-number")
	if got := controller.RetryDelayFromEnv(); got != 60 {
		t.Errorf("expected 60 for invalid value, got %d", got)
	}
}

// ── Volume policy via the reconciler ───────────────────────────────────────

func withVolumePolicy(policy string) func(*infrav1.OpenStackCluster) {
	return func(c *infrav1.OpenStackCluster) {
		if c.Annotations == nil {
			c.Annotations = make(map[string]string)
		}
		c.Annotations[controller.VolumesPolicyAnnotation] = policy
	}
}

func reconcileForVolumesCapture(t *testing.T, defaultPolicy string, clusterOpts ...func(*infrav1.OpenStackCluster)) openstack.PurgeOptions {
	t.Helper()
	opts := append([]func(*infrav1.OpenStackCluster){withFinalizer, withDeletionTimestamp}, clusterOpts...)
	cluster := newCluster("mycluster", "default", opts...)
	secret := newSecret("cloud-credentials", "default")

	var captured openstack.PurgeOptions
	r, _ := newReconciler(func(_ context.Context, o openstack.PurgeOptions) error {
		captured = o
		return nil
	}, cluster, secret)
	r.DefaultVolumesPolicy = defaultPolicy

	if _, err := r.Reconcile(context.Background(), reconcileRequest("mycluster", "default")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return captured
}

// Scenario: Global policy "delete" → volumes included in the purge
func TestReconcile_VolumesPolicy_IncludesVolumes_WhenDelete(t *testing.T) {
	opts := reconcileForVolumesCapture(t, controller.PolicyDelete)
	if !opts.IncludeVolumes {
		t.Error("expected IncludeVolumes=true for policy 'delete'")
	}
}

// Scenario: Global policy "keep" → volumes excluded from the purge
func TestReconcile_VolumesPolicy_ExcludesVolumes_WhenKeep(t *testing.T) {
	opts := reconcileForVolumesCapture(t, "keep")
	if opts.IncludeVolumes {
		t.Error("expected IncludeVolumes=false for policy 'keep'")
	}
}

// Scenario: Annotation "delete" on the cluster (overrides global keep)
func TestReconcile_VolumesPolicy_AnnotationDeleteOverridesKeepGlobal(t *testing.T) {
	opts := reconcileForVolumesCapture(t, "keep", withVolumePolicy(controller.PolicyDelete))
	if !opts.IncludeVolumes {
		t.Error("expected IncludeVolumes=true when annotation 'delete' overrides global 'keep'")
	}
}

// Scenario: Annotation "keep" on the cluster (overrides global delete)
func TestReconcile_VolumesPolicy_AnnotationKeepOverridesDeleteGlobal(t *testing.T) {
	opts := reconcileForVolumesCapture(t, controller.PolicyDelete, withVolumePolicy("keep"))
	if opts.IncludeVolumes {
		t.Error("expected IncludeVolumes=false when annotation 'keep' overrides global 'delete'")
	}
}

// ── Configurable retry delay ───────────────────────────────────────────────

// Scenario: RetryDefaultDelay = 120 → sleep called with 120 seconds
func TestReconcile_RetryDelay_UsesConfiguredDelay(t *testing.T) {
	cluster := newCluster("mycluster", "default",
		withFinalizer,
		func(c *infrav1.OpenStackCluster) {
			now := metav1.Now()
			c.DeletionTimestamp = &now
		},
	)
	secret := newSecret("cloud-credentials", "default")

	var sleptFor time.Duration
	r, _ := newReconciler(func(_ context.Context, _ openstack.PurgeOptions) error {
		return context.DeadlineExceeded // simulate purge failure
	}, cluster, secret)
	r.RetryDefaultDelay = 120
	r.SleepFunc = func(d time.Duration) { sleptFor = d }

	if _, err := r.Reconcile(context.Background(), reconcileRequest("mycluster", "default")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sleptFor != 120*time.Second {
		t.Errorf("expected sleep of 120s, got %v", sleptFor)
	}
}
