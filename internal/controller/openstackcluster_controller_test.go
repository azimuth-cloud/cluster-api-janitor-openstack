package controller_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	infrav1 "sigs.k8s.io/cluster-api-provider-openstack/api/v1beta1"

	"github.com/azimuth-cloud/cluster-api-janitor-openstack/internal/controller"
	"github.com/azimuth-cloud/cluster-api-janitor-openstack/internal/openstack"
)

var testScheme *runtime.Scheme

func init() {
	testScheme = runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(testScheme)
	_ = infrav1.AddToScheme(testScheme)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func reconcileRequest(name, namespace string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: namespace}}
}

func newReconciler(purgeFunc func(context.Context, openstack.PurgeOptions) error, objs ...client.Object) (*controller.OpenStackClusterReconciler, client.Client) {
	c := fake.NewClientBuilder().WithScheme(testScheme).WithObjects(objs...).Build()
	r := &controller.OpenStackClusterReconciler{
		Client:    c,
		Scheme:    testScheme,
		PurgeFunc: purgeFunc,
		SleepFunc: func(time.Duration) {}, // no-op: avoid real sleeps in tests
	}
	return r, c
}

func newCluster(name, namespace string, opts ...func(*infrav1.OpenStackCluster)) *infrav1.OpenStackCluster {
	c := &infrav1.OpenStackCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: infrav1.OpenStackClusterSpec{
			IdentityRef: infrav1.OpenStackIdentityReference{
				Name:      "cloud-credentials",
				CloudName: "openstack",
			},
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func withFinalizer(c *infrav1.OpenStackCluster) {
	controllerutil.AddFinalizer(c, controller.Finalizer)
}

func withDeletionTimestamp(c *infrav1.OpenStackCluster) {
	now := metav1.Now()
	c.DeletionTimestamp = &now
}

func withClusterLabel(value string) func(*infrav1.OpenStackCluster) {
	return func(c *infrav1.OpenStackCluster) {
		if c.Labels == nil {
			c.Labels = make(map[string]string)
		}
		c.Labels[controller.ClusterNameLabel] = value
	}
}

func newSecret(name, namespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Data:       map[string][]byte{"clouds.yaml": []byte("clouds: {}")},
	}
}

func getClusterOrNil(t *testing.T, c client.Client, name, namespace string) *infrav1.OpenStackCluster {
	t.Helper()
	var cluster infrav1.OpenStackCluster
	err := c.Get(context.Background(), types.NamespacedName{Name: name, Namespace: namespace}, &cluster)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("getting cluster: %v", err)
	}
	return &cluster
}

// ── US8.1: Ajouter un finalizer ───────────────────────────────────────────────

// Scenario: Cluster sans deletionTimestamp et sans finalizer → finalizer ajouté
func TestReconcile_AddsFinalizer_WhenNotPresent(t *testing.T) {
	cluster := newCluster("mycluster", "default")
	r, c := newReconciler(nil, cluster)

	if _, err := r.Reconcile(context.Background(), reconcileRequest("mycluster", "default")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := getClusterOrNil(t, c, "mycluster", "default")
	if got == nil {
		t.Fatal("cluster not found after reconcile")
	}
	if !controllerutil.ContainsFinalizer(got, controller.Finalizer) {
		t.Errorf("expected finalizer %q to be added, got finalizers: %v", controller.Finalizer, got.Finalizers)
	}
}

// Scenario: Cluster avec finalizer déjà présent → aucun changement d'état
func TestReconcile_FinalizerAlreadyPresent_Idempotent(t *testing.T) {
	cluster := newCluster("mycluster", "default", withFinalizer)
	r, c := newReconciler(nil, cluster)

	if _, err := r.Reconcile(context.Background(), reconcileRequest("mycluster", "default")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := getClusterOrNil(t, c, "mycluster", "default")
	if got == nil {
		t.Fatal("cluster not found after reconcile")
	}
	if !controllerutil.ContainsFinalizer(got, controller.Finalizer) {
		t.Errorf("expected finalizer %q to still be present", controller.Finalizer)
	}
}

// ── US8.2: Nom du cluster depuis le label ou metadata.name ───────────────────

// Scenario: Label cluster.x-k8s.io/cluster-name présent → nom du label utilisé
func TestReconcile_ClusterName_FromLabel(t *testing.T) {
	cluster := newCluster("mycluster-openstack", "default",
		withFinalizer,
		withDeletionTimestamp,
		withClusterLabel("mycluster"),
	)
	secret := newSecret("cloud-credentials", "default")

	var capturedName string
	r, _ := newReconciler(func(_ context.Context, opts openstack.PurgeOptions) error {
		capturedName = opts.ClusterName
		return nil
	}, cluster, secret)

	if _, err := r.Reconcile(context.Background(), reconcileRequest("mycluster-openstack", "default")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedName != "mycluster" {
		t.Errorf("expected ClusterName %q (from label), got %q", "mycluster", capturedName)
	}
}

// Scenario: Label absent → metadata.name utilisé
func TestReconcile_ClusterName_FallsBackToMetadataName(t *testing.T) {
	cluster := newCluster("mycluster", "default", withFinalizer, withDeletionTimestamp)
	secret := newSecret("cloud-credentials", "default")

	var capturedName string
	r, _ := newReconciler(func(_ context.Context, opts openstack.PurgeOptions) error {
		capturedName = opts.ClusterName
		return nil
	}, cluster, secret)

	if _, err := r.Reconcile(context.Background(), reconcileRequest("mycluster", "default")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedName != "mycluster" {
		t.Errorf("expected ClusterName %q (from metadata.name), got %q", "mycluster", capturedName)
	}
}

// ── US8.3: Supprimer le finalizer après nettoyage réussi ─────────────────────

// Scenario: Purge réussie → finalizer retiré
func TestReconcile_RemovesFinalizer_AfterSuccessfulPurge(t *testing.T) {
	cluster := newCluster("mycluster", "default", withFinalizer, withDeletionTimestamp)
	secret := newSecret("cloud-credentials", "default")

	r, c := newReconciler(func(_ context.Context, _ openstack.PurgeOptions) error { return nil }, cluster, secret)

	if _, err := r.Reconcile(context.Background(), reconcileRequest("mycluster", "default")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// After removing the last finalizer with DeletionTimestamp set, the fake client may GC the object.
	got := getClusterOrNil(t, c, "mycluster", "default")
	if got != nil && controllerutil.ContainsFinalizer(got, controller.Finalizer) {
		t.Errorf("expected finalizer %q to be removed after purge", controller.Finalizer)
	}
}

// Scenario: Finalizer absent au moment de la suppression → pas de purge
func TestReconcile_SkipsCleanup_WhenFinalizerAbsent(t *testing.T) {
	// Use a non-janitor finalizer to keep the cluster alive in the fake client
	// when we call Delete (which sets DeletionTimestamp instead of deleting immediately).
	cluster := newCluster("mycluster", "default")
	controllerutil.AddFinalizer(cluster, "other.finalizer.example.com")

	purgeCalled := false
	r, c := newReconciler(func(_ context.Context, _ openstack.PurgeOptions) error {
		purgeCalled = true
		return nil
	}, cluster)

	// Trigger deletion — fake client sets DeletionTimestamp (kept alive by other finalizer).
	if err := c.Delete(context.Background(), cluster); err != nil {
		t.Fatalf("marking cluster for deletion: %v", err)
	}

	if _, err := r.Reconcile(context.Background(), reconcileRequest("mycluster", "default")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if purgeCalled {
		t.Error("expected purge NOT to be called when janitor finalizer is absent")
	}
}

// ── US8.4: Mécanisme de retry via annotation ──────────────────────────────────

// Scenario: Erreur lors de la purge → annotation retry posée, Reconcile retourne nil
func TestReconcile_AnnotatesRetry_OnPurgeError(t *testing.T) {
	cluster := newCluster("mycluster", "default", withFinalizer, withDeletionTimestamp)
	secret := newSecret("cloud-credentials", "default")

	r, c := newReconciler(func(_ context.Context, _ openstack.PurgeOptions) error {
		return errors.New("purge failed")
	}, cluster, secret)

	if _, err := r.Reconcile(context.Background(), reconcileRequest("mycluster", "default")); err != nil {
		t.Fatalf("expected nil (retry handled internally), got: %v", err)
	}

	got := getClusterOrNil(t, c, "mycluster", "default")
	if got == nil {
		t.Fatal("cluster not found after reconcile")
	}
	if got.Annotations[controller.RetryAnnotation] == "" {
		t.Errorf("expected retry annotation %q to be set after purge error", controller.RetryAnnotation)
	}
}

// Scenario: Cluster supprimé entre l'erreur de purge et l'annotation retry → NotFound ignoré
func TestReconcile_IgnoresNotFound_WhenClusterDeletedDuringRetry(t *testing.T) {
	cluster := newCluster("mycluster", "default", withFinalizer, withDeletionTimestamp)
	secret := newSecret("cloud-credentials", "default")

	r, c := newReconciler(nil, cluster, secret)

	// PurgeFunc deletes the cluster mid-flight to simulate it disappearing during cleanup.
	r.PurgeFunc = func(ctx context.Context, _ openstack.PurgeOptions) error {
		// Remove finalizer first so the fake client actually deletes on Delete call.
		var cl infrav1.OpenStackCluster
		_ = c.Get(ctx, types.NamespacedName{Name: "mycluster", Namespace: "default"}, &cl)
		controllerutil.RemoveFinalizer(&cl, controller.Finalizer)
		_ = c.Update(ctx, &cl)
		_ = c.Delete(ctx, &cl)
		return fmt.Errorf("cleanup failed")
	}

	// annotateRetry will see NotFound — must be ignored, not propagated.
	if _, err := r.Reconcile(context.Background(), reconcileRequest("mycluster", "default")); err != nil {
		t.Fatalf("expected no error when cluster deleted during retry annotation, got: %v", err)
	}
}
