/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	infrav1 "sigs.k8s.io/cluster-api-provider-openstack/api/v1beta1"

	"github.com/azimuth-cloud/cluster-api-janitor-openstack/internal/openstack"
)

const (
	Finalizer = "janitor.capi.stackhpc.com"

	VolumesPolicyAnnotation    = "janitor.capi.stackhpc.com/volumes-policy"
	CredentialPolicyAnnotation = "janitor.capi.stackhpc.com/credential-policy"
	RetryAnnotation            = "janitor.capi.stackhpc.com/retry"
	ClusterNameLabel           = "cluster.x-k8s.io/cluster-name"

	PolicyDelete = "delete"

	defaultRetryDelay = 60 // seconds
)

// OpenStackClusterReconciler reconciles OpenStackCluster objects from CAPO.
type OpenStackClusterReconciler struct {
	client.Client
	Scheme               *runtime.Scheme
	DefaultVolumesPolicy string
	RetryDefaultDelay    int
	// PurgeFunc is called to clean up OpenStack resources; defaults to openstack.PurgeResources.
	PurgeFunc func(context.Context, openstack.PurgeOptions) error
	// SleepFunc is called instead of time.Sleep; defaults to time.Sleep.
	SleepFunc func(time.Duration)
}

func (r *OpenStackClusterReconciler) purge(ctx context.Context, opts openstack.PurgeOptions) error {
	if r.PurgeFunc != nil {
		return r.PurgeFunc(ctx, opts)
	}
	return openstack.PurgeResources(ctx, opts)
}

func (r *OpenStackClusterReconciler) sleep(d time.Duration) {
	if r.SleepFunc != nil {
		r.SleepFunc(d)
	} else {
		time.Sleep(d)
	}
}

//+kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=openstackclusters,verbs=get;list;watch;patch;update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;delete
//+kubebuilder:rbac:groups="",resources=namespaces,verbs=list;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=create
//+kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=get;list;watch

func (r *OpenStackClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var cluster infrav1.OpenStackCluster
	if err := r.Get(ctx, req.NamespacedName, &cluster); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	clusterName := clusterNameFor(&cluster)
	logger = logger.WithValues("clusterName", clusterName)
	logger.V(1).Info("reconciling OpenStackCluster")

	// Not deleting: ensure our finalizer is present.
	if cluster.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&cluster, Finalizer) {
			controllerutil.AddFinalizer(&cluster, Finalizer)
			if err := r.Update(ctx, &cluster); err != nil {
				return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
			}
			logger.Info("added janitor finalizer to cluster")
		}
		return ctrl.Result{}, nil
	}

	// Deleting: only act if our finalizer is present.
	if !controllerutil.ContainsFinalizer(&cluster, Finalizer) {
		logger.Info("janitor finalizer not present, skipping cleanup")
		return ctrl.Result{}, nil
	}

	// Fetch the cloud credential secret.
	secret, err := r.getSecret(ctx, cluster.Spec.IdentityRef.Name, req.Namespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("fetching identity secret: %w", err)
	}
	if secret == nil {
		logger.Error(nil, "clouds.yaml secret not found", "secretName", cluster.Spec.IdentityRef.Name)
		return ctrl.Result{}, nil
	}

	cloudsYAML := decodeSecretField(secret.Data["clouds.yaml"])
	cacert := decodeSecretField(secret.Data["cacert"])

	cloudName := cluster.Spec.IdentityRef.CloudName
	if cloudName == "" {
		cloudName = "openstack"
	}

	includeVolumes := r.volumesPolicyFor(&cluster) == PolicyDelete

	credentialPolicy := secret.Annotations[CredentialPolicyAnnotation]
	includeAppcred := credentialPolicy == PolicyDelete && len(cluster.Finalizers) == 1

	purgeErr := r.purge(ctx, openstack.PurgeOptions{
		CloudsYAML:     cloudsYAML,
		CloudName:      cloudName,
		CACert:         cacert,
		ClusterName:    clusterName,
		IncludeVolumes: includeVolumes,
		IncludeAppcred: includeAppcred,
		Logger:         logger,
	})
	if purgeErr != nil {
		logger.Error(purgeErr, "purge failed, will retry")
		r.sleep(r.retryDelay())
		if err := r.annotateRetry(ctx, &cluster); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Delete appcred secret if this is the last finalizer and policy says so.
	if credentialPolicy == PolicyDelete {
		if len(cluster.Finalizers) == 1 {
			if err := r.deleteSecret(ctx, secret.Name, req.Namespace); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("deleting credential secret: %w", err)
			}
			logger.Info("cloud credential secret deleted")
		} else {
			// Other finalizers still present; trigger a retry when they are removed.
			other := otherFinalizer(cluster.Finalizers, Finalizer)
			logger.Info("waiting for other finalizer before deleting appcred", "otherFinalizer", other)
			r.sleep(5 * time.Second)
			if err := r.annotateRetry(ctx, &cluster); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
	}

	// Remove our finalizer.
	controllerutil.RemoveFinalizer(&cluster, Finalizer)
	if err := r.Update(ctx, &cluster); err != nil {
		return ctrl.Result{}, fmt.Errorf("removing finalizer: %w", err)
	}
	logger.Info("removed janitor finalizer from cluster")
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *OpenStackClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&infrav1.OpenStackCluster{}).
		Complete(r)
}

// clusterNameFor returns the cluster name to use for resource cleanup.
// It prefers the cluster.x-k8s.io/cluster-name label over metadata.name.
func clusterNameFor(cluster *infrav1.OpenStackCluster) string {
	if name, ok := cluster.Labels[ClusterNameLabel]; ok {
		return name
	}
	return cluster.Name
}

func (r *OpenStackClusterReconciler) volumesPolicyFor(cluster *infrav1.OpenStackCluster) string {
	if ann, ok := cluster.Annotations[VolumesPolicyAnnotation]; ok {
		return ann
	}
	if r.DefaultVolumesPolicy != "" {
		return r.DefaultVolumesPolicy
	}
	return PolicyDelete
}

func (r *OpenStackClusterReconciler) retryDelay() time.Duration {
	d := r.RetryDefaultDelay
	if d <= 0 {
		d = defaultRetryDelay
	}
	return time.Duration(d) * time.Second
}

func (r *OpenStackClusterReconciler) annotateRetry(ctx context.Context, cluster *infrav1.OpenStackCluster) error {
	patch := client.MergeFrom(cluster.DeepCopy())
	if cluster.Annotations == nil {
		cluster.Annotations = make(map[string]string)
	}
	cluster.Annotations[RetryAnnotation] = randString(8)
	return r.Patch(ctx, cluster, patch)
}

func (r *OpenStackClusterReconciler) getSecret(ctx context.Context, name, namespace string) (*corev1.Secret, error) {
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &secret, nil
}

func (r *OpenStackClusterReconciler) deleteSecret(ctx context.Context, name, namespace string) error {
	var secret corev1.Secret
	secret.Name = name
	secret.Namespace = namespace
	return r.Delete(ctx, &secret)
}

// decodeSecretField base64-decodes a secret data field if needed.
// Kubernetes stores secret data already base64-decoded in the Go API.
func decodeSecretField(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return string(data) // already raw bytes from Kubernetes API
	}
	return string(decoded)
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func otherFinalizer(finalizers []string, skip string) string {
	for _, f := range finalizers {
		if f != skip {
			return f
		}
	}
	return ""
}

// DefaultVolumesFromEnv reads CAPI_JANITOR_DEFAULT_VOLUMES_POLICY from environment.
func DefaultVolumesFromEnv() string {
	if v := os.Getenv("CAPI_JANITOR_DEFAULT_VOLUMES_POLICY"); v != "" {
		return v
	}
	return PolicyDelete
}

// RetryDelayFromEnv reads CAPI_JANITOR_RETRY_DEFAULT_DELAY from environment.
func RetryDelayFromEnv() int {
	if v := os.Getenv("CAPI_JANITOR_RETRY_DEFAULT_DELAY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultRetryDelay
}
