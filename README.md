# cluster-api-janitor-openstack

`cluster-api-janitor-openstack` is a Kubernetes operator that cleans up resources
created in [OpenStack](https://www.openstack.org/) by the
[OpenStack Cloud Controller Manager (OCCM)](https://github.com/kubernetes/cloud-provider-openstack/blob/master/docs/openstack-cloud-controller-manager/using-openstack-cloud-controller-manager.md)
and
[Cinder CSI plugin](https://github.com/kubernetes/cloud-provider-openstack/blob/master/docs/cinder-csi-plugin/using-cinder-csi-plugin.md)
for Kubernetes clusters created using the
[Cluster API OpenStack infrastructure provider](https://github.com/kubernetes-sigs/cluster-api-provider-openstack).

## Installation

`cluster-api-janitor-openstack` can be installed using [Helm](https://helm.sh):

```sh
helm repo add \
  cluster-api-janitor-openstack \
  https://azimuth-cloud.github.io/cluster-api-janitor-openstack

# Use the latest version from the main branch
helm upgrade \
  cluster-api-janitor-openstack \
  cluster-api-janitor-openstack/cluster-api-janitor-openstack \
  --install
```

## Tox for unittests and linting

We use tox to run unit tests and linters across the code.
To run all the checks, including efforts to automatically
fix linting issues, please run:

```sh
tox
```

You can run individual unit tests by running:

```sh
tox -e py3 -- <name-of-unit-test>
```

## Configuration

`cluster-api-janitor-openstack` will always clean up
[Octavia loadbalancers](https://docs.openstack.org/octavia/latest/), and associated
[floating IPs](https://docs.openstack.org/neutron/latest/), that are created by
the OCCM for `LoadBalancer` services on Cluster API clusters.

By default, [Cinder volumes](https://docs.openstack.org/cinder/latest/) created by the
Cinder CSI plugin for `PersistentVolumeClaim`s are also cleaned up. However this behaviour
carries a risk of deleting important data, so can be customised in two ways.

The operator default can be changed to `keep`, meaning that volumes provisioned by the
Cinder CSI plugin will be kept unless overridden by the cluster:

```sh
helm upgrade ... --set defaultVolumesPolicy=keep
```

Regardless of the operator default, individual `OpenStackCluster`s can also be annotated
to indicate whether volumes for that cluster should be kept or removed:

```yaml
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha7
kind: OpenStackCluster
metadata:
  name: my-cluster
  annotations:
    janitor.capi.stackhpc.com/volumes-policy: "keep|delete"
```

> **NOTE**: Any value other than `delete` means volumes will be kept.

### User-configurable behaviour

Annotations on the Kubernetes resources are only available to administrators with
access to the Cluster API management cluster's Kubernetes API; therefore, the Janitor
also provides an alternative user-facing mechanism for marking volumes which should
not be deleted during cluster clean up. This is done by adding a property to the
OpenStack volume using:

```
openstack volume set --property janitor.capi.azimuth-cloud.com/keep='true' <volume-name-or-id>
```

Any value other than 'true' will result in the volume being deleted when the workload
cluster is deleted.

## How it works

`cluster-api-janitor-openstack` watches for `OpenStackCluster`s being created and adds its
own finalizer to them. This prevents the `OpenStackCluster`, and hence the corresponding
Cluster API `Cluster`, from being removed until the finalizer is removed.

`cluster-api-janitor-openstack` then waits for the `OpenStackCluster` to be deleted
(specifically, it waits for the `deletionTimestamp` to be set, indicating that a deletion
has been requested), at which point it uses the credential from
`OpenStackCluster.spec.identityRef` to remove any dangling resources that were created by
the OCCM or Cinder CSI with the same cluster name as the cluster being deleted.
The cluster name is determined by the `cluster.x-k8s.io/cluster-name` label on the
OpenStackCluster resource, if present.
If the label is not set, the name of the OpenStackCluster resource (`metadata.name`) is
used instead.
Once all the resources have been deleted, the finalizer is removed.

> **WARNING**
>
> The cluster name of the OCCM and Cinder CSI **must** be set to the `metadata.name`
> of the OpenStackCluster resource, or to the value of the `cluster.x-k8s.io/cluster-name`
> label if it is present on the OpenStackCluster resource.
>
> For instance, the `openstack-cluster` chart from the
> [capi-helm-charts](https://github.com/azimuth-cloud/capi-helm-charts) ensures that this happens
> automatically and sets the OpenStackCluster's `metadata.name` for OCCM and Cinder CSI.

The advantage of this approach vs. a task that runs before the cluster deletion is started
is that the external resource deletion happens _after_ all the machines have been deleted,
meaning that there is no chance of racing with the OCCM and/or Cinder CSI still running on
the cluster that may continue to try and replace resources that are cleaned up.

It is not possible to run this cleanup as a post cluster deletion task, because some of the
resources created by the OCCM may actually block cluster deletion completely. For example,
a load-balancer created by the OCCM for a `LoadBalancer` service maintains a port on the cluster
network, meaning that the network cannot be cleaned up by the Cluster API OpenStack provider
and preventing deletion of the cluster.
