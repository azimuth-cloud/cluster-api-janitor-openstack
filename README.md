# cluster-api-janitor-openstack

`cluster-api-janitor-openstack` is a Kubernetes operator that cleans up resources
created in [OpenStack](https://www.openstack.org/) by the
[OpenStack Cloud Controller Manager (OCCM)](https://github.com/kubernetes/cloud-provider-openstack/blob/master/docs/openstack-cloud-controller-manager/using-openstack-cloud-controller-manager.md)
and the
[Cinder CSI plugin](https://github.com/kubernetes/cloud-provider-openstack/blob/master/docs/cinder-csi-plugin/using-cinder-csi-plugin.md)
for Kubernetes clusters created with the
[Cluster API OpenStack infrastructure provider (CAPO)](https://github.com/kubernetes-sigs/cluster-api-provider-openstack).

The operator watches `OpenStackCluster` resources and, upon deletion, removes any
dangling OpenStack resources (floating IPs, load balancers, security groups, Cinder
volumes and snapshots, and the application credential) that would otherwise be left
behind after the CAPI cluster is gone.

## Requirements

| Tool | Minimum version |
|---|---|
| Go | 1.26 |
| Kubernetes | 1.29 |
| CAPO | 0.14 |
| Helm | 3.x |

## How it works

1. When an `OpenStackCluster` is created, the operator adds its finalizer
   (`janitor.capi.stackhpc.com`) to the resource.
2. When the `OpenStackCluster` is marked for deletion (`deletionTimestamp` set),
   the operator authenticates to OpenStack using the credential referenced by
   `spec.identityRef` and deletes all resources tagged with the cluster name.
3. The cluster name is taken from the `cluster.x-k8s.io/cluster-name` label if
   present, falling back to `metadata.name`.
4. Once the purge succeeds the finalizer is removed and the `OpenStackCluster` can
   be fully deleted.
5. If the purge fails, the operator sets a retry annotation
   (`janitor.capi.stackhpc.com/retry`) and returns without error, triggering a
   re-reconcile.

> **Why a finalizer instead of a post-delete job?**
>
> Some OCCM-created load balancers hold references to the cluster network, which
> prevents the Cluster API OpenStack provider from deleting that network. Running
> cleanup *before* the network is torn down (but *after* all machines are gone)
> avoids this deadlock and eliminates any race with a still-running OCCM.

## Resources cleaned up

| OpenStack service | Resources |
|---|---|
| Neutron | Floating IPs associated with `LoadBalancer` services |
| Octavia | Load balancers with name prefix `kube_service_<cluster>_` |
| Neutron | Security groups matching the OCCM naming convention |
| Cinder | Volumes provisioned by the Cinder CSI (configurable — see below) |
| Cinder | Snapshots of those volumes |
| Keystone | The application credential used by the cluster (if authorised) |

## Configuration

### Volume deletion policy

Cinder volumes are deleted by default. This can be changed at two levels:

**Operator-wide default** (via Helm):

```sh
helm upgrade ... --set defaultVolumesPolicy=keep
```

**Per-cluster override** (annotation on `OpenStackCluster`):

```yaml
apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
kind: OpenStackCluster
metadata:
  name: my-cluster
  annotations:
    janitor.capi.stackhpc.com/volumes-policy: "keep"   # or "delete"
```

> Any value other than `delete` means volumes will be kept.

**Per-volume override** (set directly on the OpenStack volume):

```sh
openstack volume set --property janitor.capi.azimuth-cloud.com/keep=true <volume>
```

Any value other than `true` results in the volume being deleted.

### Retry delay

When cleanup fails, the operator waits before re-queuing. The default delay is
60 seconds and can be changed via Helm:

```sh
helm upgrade ... --set retryDefaultDelay=120
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `CAPI_JANITOR_DEFAULT_VOLUMES_POLICY` | `delete` | Operator-wide volume policy |
| `CAPI_JANITOR_RETRY_DEFAULT_DELAY` | `60` | Retry delay in seconds |

## Installation

```sh
helm repo add \
  cluster-api-janitor-openstack \
  https://azimuth-cloud.github.io/cluster-api-janitor-openstack

helm upgrade \
  cluster-api-janitor-openstack \
  cluster-api-janitor-openstack/cluster-api-janitor-openstack \
  --install
```

## Development

### Build

```sh
go build ./...
```

### Run tests

```sh
go test ./...
```

The test suite covers 108 unit tests across 4 packages using only the standard
`testing` package and `controller-runtime`'s fake client — no external cluster
required.

### Lint and format

```sh
go fmt ./...
go vet ./...
```

### Makefile targets

```sh
make help          # list all targets
make generate      # regenerate DeepCopy methods
make manifests     # regenerate CRD/RBAC YAML
make fmt           # go fmt
make vet           # go vet
make test          # go test (excludes e2e)
make build         # go build ./cmd/main.go
```

## Building the OCI image

### Nix (reproducible, multi-arch + SBOM)

CI uses `nix-build` for reproducible builds. The `tests` derivation runs
`go fmt`, `go vet`, and the full unit-test suite inside the Nix sandbox — no
external toolchain needed:

```sh
# CI check: go fmt + go vet + 108 unit tests
nix-build nix -A tests

# Build the manager binary only
nix-build nix -A manager

# Build the amd64 OCI image
nix-build nix -A image

# Build the arm64 OCI image (cross-compiled from amd64)
nix-build nix -A image-arm64

# Generate the CycloneDX SBOM
nix-build nix -A sbom
```

> **`nix/nixpkgs.nix`** pins `nixos-26.05` (Go 1.26+).
> **`vendorHash`** in `nix/default.nix` is set to `sha256-5p5z+fzRkBk6rIb3DWwA3jsF4MdMVAwKHz7xza09fCc=`
> (run `nix-build nix -A manager` after any `go.mod` change — the build will
> fail and print the new hash to substitute).

**Binary linkage note**: on macOS the local build produces a darwin/arm64 Mach-O
(dynamically linked against system libraries — normal for Go on Darwin). The
arm64 image produced via `pkgsCross.aarch64-multiplatform` contains a Linux ELF
dynamically linked against glibc; `buildLayeredImage` automatically includes the
full Nix closure (glibc and its dependencies) so the image is self-contained and
runs correctly in Kubernetes.

## Observability

### Prometheus metrics

| Metric | Labels | Description |
|---|---|---|
| `capi_janitor_cleanups_total` | `result="success\|failure"` | Total cleanup attempts |

### Kubernetes events

| Reason | Type | Emitted when |
|---|---|---|
| `CleanupSucceeded` | Normal | OpenStack purge completed successfully |
| `CleanupFailed` | Warning | OpenStack purge returned an error |

## Project layout

```
cmd/                        # Operator entry point
internal/
  controller/               # Reconciler, metrics, config
  openstack/                # Authentication, resource discovery & deletion
chart/                      # Helm chart
  templates/
  tests/                    # helm-unittest tests
nix/                        # Reproducible OCI build + SBOM (no Flake)
config/                     # Kustomize bases (RBAC, manager, Prometheus)
test/e2e/                   # End-to-end test suite (Ginkgo)
```
