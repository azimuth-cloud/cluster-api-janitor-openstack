# Go Rewrite

## Context

The current project is written in Python (asyncio + kopf + easykube + httpx). It is a Kubernetes operator that cleans up OpenStack resources left behind by OCCM and the Cinder CSI when Cluster API clusters are deleted.

The rewrite follows TDD: Gherkin tests are written first, then the implementations.

Scaffolding tool: **kubebuilder**.

---

## Audit of the Existing Python Code

### Main Modules

| File | Role |
|---|---|
| `capi_janitor/openstack/openstack.py` | OpenStack client: authentication, service catalog, paginated REST resources |
| `capi_janitor/openstack/operator.py` | Operator logic: kopf handlers, resource filters, OpenStack purge |

### Covered Features

**OpenStack Authentication**
- Only `v3applicationcredential`
- X-Auth-Token management (refresh with asyncio mutex)
- Custom CA certificate support (cacert from K8s secret)
- Service catalog filtered by interface (public/internal/admin) and region

**Resource Filtering**
- Floating IPs: description `"Floating IP for Kubernetes external service … from cluster <name>"`
- Octavia Load Balancers: name `kube_service_<cluster>_*`
- Security Groups: description `"Security Group for Service LoadBalancer in cluster <name>"`
- Cinder Volumes: metadata `cinder.csi.openstack.org/cluster == <name>`, unless property `janitor.capi.azimuth-cloud.com/keep == true`
- Cinder Snapshots: same cluster metadata

**Deletion Policy**
- Volumes: configurable via env var `CAPI_JANITOR_DEFAULT_VOLUMES_POLICY` (default `delete`) and annotation `janitor.capi.stackhpc.com/volumes-policy` per cluster
- Application Credential: deleted if annotation `janitor.capi.stackhpc.com/credential-policy: delete` on the secret AND it is the last finalizer

**Kubernetes Lifecycle**
- Finalizer `janitor.capi.stackhpc.com` on `OpenStackCluster`
- Cluster name: label `cluster.x-k8s.io/cluster-name` takes priority, otherwise `metadata.name`
- Retry via random annotation `janitor.capi.stackhpc.com/retry` (triggers a new event)
- Configurable backoff `CAPI_JANITOR_RETRY_DEFAULT_DELAY` (default 60s)

**Error Handling**
- HTTP 400/409 during deletion: silent retry
- HTTP 404 during catalog fetch: authentication considered failed (no fatal error)
- HTTP 422 during finalizer patch: kopf `TemporaryError`
- Catalog error `volumev3` → fallback to `block-storage`

### Existing Tests

| File | What is tested |
|---|---|
| `test_openstack.py` | Successful auth, 404, missing interface, missing region, multiple services |
| `test_operator.py` | FIP/LB/SG/volume/snapshot filtering; `empty()`; `try_delete()`; event handler (add finalizer, skip, purge); auth error in purge |

**Notable gap**: `test_purge_openstack_resources_success` is commented out (mock complexity).

### Helm Chart

- `ClusterRole`: namespaces (list/watch), events (create), secrets (get/delete), openstackclusters (list/get/watch/patch), CRDs (list/get/watch)
- Value `defaultVolumesPolicy: delete`
- Image: `ghcr.io/azimuth-cloud/cluster-api-janitor-openstack`

### Pending PRs to Integrate

| PR | Title | Impact |
|---|---|---|
| #261 | Fix leaving Azimuth cluster loadbalancers behind | Adds detection of Azimuth LBs (`kube_service_<cluster>_` + LBs named differently by Azimuth) |

---

## Agile Roadmap

---

### Epic 1 — OpenStack Authentication

#### US1.1 — Authentication via Application Credential v3

```gherkin
Feature: OpenStack Authentication via Application Credential
  In order to access OpenStack APIs
  As an operator
  I want to authenticate using a v3 Application Credential

  Scenario: Successful authentication
    Given a clouds.yaml with auth_type "v3applicationcredential"
    And a valid application_credential_id and application_credential_secret
    When the operator initialises the OpenStack connection
    Then an X-Auth-Token is obtained from Keystone
    And the service catalog is loaded

  Scenario: Token refresh on expiry
    Given an expired X-Auth-Token
    When the operator makes an API call
    Then a new token is requested from Keystone
    And the original call is replayed with the new token

  Scenario: Authentication with unsupported type
    Given a clouds.yaml with auth_type "password"
    When the operator attempts to create a Cloud client
    Then an UnsupportedAuthenticationError is raised
```

#### US1.2 — Service Catalog Filtering by Interface and Region

```gherkin
Feature: OpenStack Service Catalog
  Scenario: Endpoint selected by configured interface
    Given a catalog with "public" and "internal" endpoints
    And the configured interface is "public"
    When the catalog is loaded
    Then only "public" endpoints are retained

  Scenario: Endpoint selected by configured region
    Given a catalog with endpoints for "RegionOne" and "RegionTwo"
    And the configured region is "RegionOne"
    When the catalog is loaded
    Then only "RegionOne" endpoints are retained

  Scenario: No region configured
    Given a catalog with endpoints in multiple regions
    And no region is configured
    When the catalog is loaded
    Then the first endpoint matching the interface is retained for each service
```

#### US1.3 — Revoked or Invalid Credential Handling

```gherkin
Feature: Invalid OpenStack Credential
  Scenario: Application credential deleted before purge
    Given an OpenStack cluster being deleted
    And the application credential has already been deleted
    When the operator attempts to authenticate
    Then is_authenticated returns false
    And if include_appcred is true, a warning is emitted and the purge stops cleanly
    And if include_appcred is false, an AuthenticationError is raised

  Scenario: Catalog returns 404
    Given a valid Keystone URL but the catalog returns 404
    When the operator loads the catalog
    Then is_authenticated returns false
    And no fatal error is raised
```

#### US1.4 — Custom CA Certificate Support

```gherkin
Feature: Custom CA Certificate
  Scenario: CA provided in the Kubernetes secret
    Given a Kubernetes secret containing a "cacert" entry
    When the operator initialises the TLS transport
    Then the CA is loaded into the SSL context
    And HTTPS calls to OpenStack use this CA for verification

  Scenario: No CA provided
    Given a Kubernetes secret without a "cacert" entry
    When the operator initialises the TLS transport
    Then the system CA is used for TLS verification
```

---

### Epic 2 — Floating IP Cleanup

#### US2.1 — Identify Floating IPs of a Cluster

```gherkin
Feature: Identifying Floating IPs of a Cluster
  Scenario: FIP belonging to the cluster
    Given a list of OpenStack Floating IPs
    And a FIP with description "Floating IP for Kubernetes external service from cluster mycluster"
    When the FIPs of cluster "mycluster" are listed
    Then this FIP is included in the result

  Scenario: FIP from another cluster
    Given a FIP with description "Floating IP for Kubernetes external service from cluster othercluster"
    When the FIPs of cluster "mycluster" are listed
    Then this FIP is excluded from the result

  Scenario: FIP without a Kubernetes description
    Given a FIP with description "Some other description"
    When the FIPs of cluster "mycluster" are listed
    Then this FIP is excluded from the result
```

#### US2.2 — Delete Floating IPs

```gherkin
Feature: Floating IP Deletion
  Scenario: Successful deletion
    Given a FIP belonging to cluster "mycluster"
    When the FIP purge is triggered
    Then the FIP is deleted via the Neutron API
    And an INFO log is emitted

  Scenario: HTTP 400 error during deletion
    Given a FIP deletion returns HTTP 400
    When the purge attempts to delete the FIP
    Then a warning is emitted
    And deletion continues for other FIPs
    And check_fips is true to trigger a verification

  Scenario: HTTP 500 error during deletion
    Given a FIP deletion returns HTTP 500
    When the purge attempts to delete the FIP
    Then an exception is propagated

  Scenario: FIP deletion confirmed via polling
    Given a FIP still appears in a first verification listing (OpenStack PENDING_DELETE)
    When the purge polls again shortly after
    And the FIP has disappeared
    Then no error is raised

  Scenario: FIP still present after exhausting verification attempts
    Given a FIP still appears in every verification listing
    When the purge exhausts its polling attempts
    Then an error is returned mentioning the cluster name
```

> Deletion verification for FIPs, LBs, security groups, volumes and snapshots
> (Epics 2 to 6) shares a common polling mechanism: verify immediately after
> issuing the deletes, then retry a bounded number of times with a fixed
> delay between attempts if the resource is still listed. This absorbs
> OpenStack's eventual consistency (`PENDING_DELETE` states) without
> incurring a wait when nothing needs one.

---

### Epic 3 — Octavia Load Balancer Cleanup

#### US3.1 — Identify Kubernetes Load Balancers of a Cluster

```gherkin
Feature: Identifying Kubernetes Load Balancers
  Scenario: LB belonging to the cluster
    Given an LB with name "kube_service_mycluster_api"
    When the LBs of cluster "mycluster" are listed
    Then this LB is included in the result

  Scenario: LB from another cluster
    Given an LB with name "kube_service_othercluster_api"
    When the LBs of cluster "mycluster" are listed
    Then this LB is excluded from the result

  Scenario: LB without kube_service prefix
    Given an LB with name "fake_service_mycluster_api"
    When the LBs of cluster "mycluster" are listed
    Then this LB is excluded from the result
```

#### US3.2 — Identify Azimuth Load Balancers (PR #261)

```gherkin
Feature: Identifying Azimuth Load Balancers
  Scenario: Azimuth LB belonging to the cluster
    Given an Azimuth LB identifiable as belonging to cluster "mycluster"
    When the LBs of cluster "mycluster" are listed
    Then this Azimuth LB is included in the result

  Scenario: HTTP error during LB listing
    Given the Octavia API returns an HTTP error during listing
    When the LBs of cluster "mycluster" are listed
    Then an ERROR log is emitted with the HTTP code
    And no exception is propagated
    And a warning indicates that LBs may remain

  Scenario: HTTP error while verifying LB deletion after polling
    Given LBs were deleted for cluster "mycluster"
    And the Octavia API returns an HTTP error while verifying their deletion
    When the verification polling exhausts its attempts due to the error
    Then an ERROR log is emitted
    And no exception is propagated
```

> Unlike the other resource types, LB verification failures stay non-fatal
> (logged only) in both cases above — before and after the deletes are
> issued — since Octavia listing is known to be slower/less reliable than
> Neutron or Cinder (see PR #261).

#### US3.3 — Delete Load Balancers with Cascade

```gherkin
Feature: Cascaded Load Balancer Deletion
  Scenario: Successful deletion with cascade
    Given an LB belonging to cluster "mycluster"
    When the LB purge is triggered
    Then the LB is deleted with the cascade=true parameter
    And associated Octavia resources (listeners, pools, members) are deleted
```

---

### Epic 4 — Security Group Cleanup

#### US4.1 — Identify Security Groups of a Cluster

```gherkin
Feature: Identifying Security Groups of a Cluster
  Scenario: SG belonging to the cluster
    Given an SG with description "Security Group for Service LoadBalancer in cluster mycluster"
    When the SGs of cluster "mycluster" are listed
    Then this SG is included in the result

  Scenario: SG from another cluster
    Given an SG with description "Security Group for Service LoadBalancer in cluster othercluster"
    When the SGs of cluster "mycluster" are listed
    Then this SG is excluded from the result
```

#### US4.2 — Delete Security Groups

```gherkin
Feature: Security Group Deletion
  Scenario: Successful deletion
    Given an SG belonging to cluster "mycluster"
    When the SG purge is triggered
    Then the SG is deleted via the Neutron API

  Scenario: SG still in use (HTTP 409)
    Given an SG deletion returns HTTP 409
    When the purge attempts to delete the SG
    Then a warning is emitted
    And check_secgroups is true for a later verification
```

---

### Epic 5 — Cinder Volume Management

#### US5.1 — Identify Volumes of a Cluster

```gherkin
Feature: Identifying Cinder Volumes of a Cluster
  Scenario: Volume belonging to the cluster without keep flag
    Given a volume with metadata "cinder.csi.openstack.org/cluster" = "mycluster"
    And the property "janitor.capi.azimuth-cloud.com/keep" is absent or != "true"
    When the volumes of cluster "mycluster" are listed
    Then this volume is included in the result

  Scenario: Volume flagged keep by the user
    Given a volume with metadata "cinder.csi.openstack.org/cluster" = "mycluster"
    And the property "janitor.capi.azimuth-cloud.com/keep" = "true"
    When the volumes of cluster "mycluster" are listed
    Then this volume is excluded from the result

  Scenario: Volume from another cluster
    Given a volume with metadata "cinder.csi.openstack.org/cluster" = "othercluster"
    When the volumes of cluster "mycluster" are listed
    Then this volume is excluded from the result

  Scenario: Volume without CSI metadata
    Given a volume without metadata "cinder.csi.openstack.org/cluster"
    When the volumes of cluster "mycluster" are listed
    Then this volume is excluded from the result
```

#### US5.2 — Volume Deletion Policy

```gherkin
Feature: Volume Deletion Policy
  Scenario: Global policy "delete" (default)
    Given the environment variable CAPI_JANITOR_DEFAULT_VOLUMES_POLICY is not set
    When a cluster is deleted without a volumes annotation
    Then the cluster's volumes are deleted

  Scenario: Global policy "keep"
    Given CAPI_JANITOR_DEFAULT_VOLUMES_POLICY = "keep"
    When a cluster is deleted without a volumes annotation
    Then the cluster's volumes are kept

  Scenario: Annotation "delete" on the cluster (overrides global keep)
    Given CAPI_JANITOR_DEFAULT_VOLUMES_POLICY = "keep"
    And the annotation "janitor.capi.stackhpc.com/volumes-policy" = "delete" on the OpenStackCluster
    When the cluster is deleted
    Then the cluster's volumes are deleted

  Scenario: Annotation "keep" on the cluster (overrides global delete)
    Given CAPI_JANITOR_DEFAULT_VOLUMES_POLICY = "delete"
    And the annotation "janitor.capi.stackhpc.com/volumes-policy" = "keep" on the OpenStackCluster
    When the cluster is deleted
    Then the cluster's volumes are kept
```

---

### Epic 6 — Cinder Snapshot Management

#### US6.1 — Identify and Delete Snapshots of a Cluster

```gherkin
Feature: Cinder Snapshots of a Cluster
  Scenario: Snapshot belonging to the cluster
    Given a snapshot with metadata "cinder.csi.openstack.org/cluster" = "mycluster"
    When the snapshots of cluster "mycluster" are listed
    Then this snapshot is included in the result

  Scenario: Snapshot from another cluster
    Given a snapshot with metadata "cinder.csi.openstack.org/cluster" = "othercluster"
    When the snapshots of cluster "mycluster" are listed
    Then this snapshot is excluded from the result

  Scenario: Snapshots deleted before volumes
    Given snapshots and volumes belonging to cluster "mycluster"
    When the purge is triggered with include_volumes = true
    Then snapshots are deleted first
    And volumes are deleted afterwards
```

---

### Epic 7 — Application Credential Management

#### US7.1 — Delete the OpenStack Application Credential

```gherkin
Feature: Application Credential Deletion
  Scenario: Deletion authorised (last finalizer)
    Given the annotation "janitor.capi.stackhpc.com/credential-policy" = "delete" on the secret
    And the operator's finalizer is the only finalizer present
    When the purge of OpenStack resources is complete
    Then the Application Credential is deleted via the Identity API
    And the Kubernetes secret containing clouds.yaml is deleted

  Scenario: Other finalizers still present
    Given the annotation "credential-policy" = "delete" on the secret
    And other finalizers are still present on the OpenStackCluster
    When the purge is complete
    Then the Application Credential is not deleted
    And a FinalizerStillPresentError is raised to trigger a retry

  Scenario: Application Credential cannot be deleted (403)
    Given the Application Credential is restricted (no unrestricted flag)
    When the appcred deletion is attempted
    Then a warning is emitted
    And the Kubernetes secret deletion proceeds anyway
```

---

### Epic 8 — Kubernetes Lifecycle (Finalizer Pattern)

#### US8.1 — Add a Finalizer on Creation

```gherkin
Feature: Adding the Janitor Finalizer to OpenStackCluster
  Scenario: Cluster without deletionTimestamp and without janitor finalizer
    Given an OpenStackCluster without deletionTimestamp
    And without finalizer "janitor.capi.stackhpc.com"
    When an event is received for this cluster
    Then the finalizer "janitor.capi.stackhpc.com" is added via patch
    And an INFO log confirms the addition

  Scenario: Cluster with finalizer already present
    Given an OpenStackCluster without deletionTimestamp
    And with the finalizer "janitor.capi.stackhpc.com" already present
    When an event is received
    Then no patch is made
```

#### US8.2 — Cluster Name from Label or metadata.name

```gherkin
Feature: Cluster Name Resolution
  Scenario: Label cluster.x-k8s.io/cluster-name present
    Given an OpenStackCluster with label "cluster.x-k8s.io/cluster-name" = "myapp"
    And metadata.name = "myapp-openstack"
    When the operator resolves the cluster name for cleanup
    Then the name "myapp" is used

  Scenario: Label absent
    Given an OpenStackCluster without label "cluster.x-k8s.io/cluster-name"
    And metadata.name = "mycluster"
    When the operator resolves the cluster name
    Then the name "mycluster" is used
```

#### US8.3 — Remove the Finalizer after Successful Cleanup

```gherkin
Feature: Finalizer Removal after Purge
  Scenario: Successful purge
    Given an OpenStackCluster being deleted
    And all OpenStack resources have been deleted
    When the purge completes without error
    Then the finalizer "janitor.capi.stackhpc.com" is removed via patch
    And an INFO log confirms the finalizer removal

  Scenario: Finalizer absent at removal time
    Given an OpenStackCluster with deletionTimestamp
    And without the finalizer "janitor.capi.stackhpc.com"
    When an event is received
    Then no purge is triggered
    And an INFO log indicates the finalizer is absent
```

#### US8.4 — Retry Mechanism via Annotation

```gherkin
Feature: Retry via Random Annotation
  Scenario: Transient error during purge
    Given a purge that fails with a ResourcesStillPresentError
    When the operator handles the error
    Then after a backoff delay (5s for ResourcesStillPresent)
    And a random annotation "janitor.capi.stackhpc.com/retry" is set on the OpenStackCluster
    And a new event is triggered to replay the purge

  Scenario: Unknown error during purge
    Given a purge that fails with an unclassified exception
    When the operator handles the error
    Then the delay is CAPI_JANITOR_RETRY_DEFAULT_DELAY (default 60s)
    And the exception is logged with a stack trace

  Scenario: Resource deleted between the error and the retry
    Given the OpenStackCluster is deleted during backoff
    When the operator attempts to annotate the resource
    Then the 404 ApiError is ignored
```

---

### Epic 9 — Operator Configuration

#### US9.1 — Configuration via Environment Variables

```gherkin
Feature: Configuration via Environment Variables
  Scenario: Default volumes policy configured
    Given CAPI_JANITOR_DEFAULT_VOLUMES_POLICY = "keep"
    When the operator starts
    Then the default policy for all clusters is "keep"

  Scenario: Configurable retry delay
    Given CAPI_JANITOR_RETRY_DEFAULT_DELAY = "120"
    When an unclassified error occurs
    Then the retry delay is 120 seconds
```

---

### Epic 10 — Packaging and Deployment

#### US10.1 — Secure Image (Go Dockerfile)

```gherkin
Feature: Secure OCI Image for the Go Operator
  Scenario: Multi-stage Go build
    Given the Go operator source code
    When the Dockerfile is built
    Then the builder uses golang:1.26
    And the runtime uses gcr.io/distroless/static:nonroot (UID 65532)

  Scenario: Image security
    Given the built image
    Then the process runs as non-root (UID 65532)
    And the root filesystem is read-only
    And all Linux capabilities are dropped
```

#### US10.2 — Helm Chart

```gherkin
Feature: Deployment via Helm Chart
  Scenario: Installation with default values
    Given the cluster-api-janitor-openstack Helm chart
    When helm install is executed
    Then a Deployment, ServiceAccount, ClusterRole, and ClusterRoleBinding are created
    And the default volumes policy is "delete"
    And the default retry delay is 60 seconds

  Scenario: Override volumes policy
    Given helm install with --set defaultVolumesPolicy=keep
    When the chart is deployed
    Then the variable CAPI_JANITOR_DEFAULT_VOLUMES_POLICY = "keep" is injected into the pod

  Scenario: Health probes active
    Given the deployed Deployment
    Then a livenessProbe on /healthz:8081 is configured
    And a readinessProbe on /readyz:8081 is configured

  Scenario: Complete RBAC
    Given the deployed ClusterRole
    Then the "update" verb is present on openstackclusters
    (required for r.Update during finalizer management)
```

#### US10.3 — OCI Build via Nix (without Flake) and SBOM

```gherkin
Feature: Reproducible OCI Build via Nix and SBOM Generation
  Scenario: Build the amd64 image with Nix
    Given the nix/default.nix file
    When nix-build nix -A image is executed
    Then an amd64 OCI image is produced (dockerTools.buildLayeredImage)
    And the image runs as User 65532:65532

  Scenario: Build the arm64 image by cross-compilation
    Given the nix/default.nix file
    When nix-build nix -A image-arm64 is executed
    Then an arm64 OCI image is produced via pkgsCross.aarch64-multiplatform
    And both images are combined into a multi-arch manifest via skopeo + docker manifest

  Scenario: CycloneDX SBOM generation
    Given the compiled Go binary
    When nix-build nix -A sbom is executed
    Then an sbom.cdx.json file in CycloneDX format is produced
    And it lists all Go modules (extracted from the buildinfo embedded in the binary)
    And it is uploaded as an artefact of the GitHub Actions workflow
```

---

### Epic 11 — Observability

#### US11.1 — Prometheus Metrics

```gherkin
Feature: Prometheus Metrics
  Scenario: Successful purge → success counter incremented
    Given a cluster being deleted
    When the OpenStack purge succeeds
    Then capi_janitor_cleanups_total{result="success"} is incremented by 1

  Scenario: Failed purge → failure counter incremented
    Given a cluster being deleted
    When the OpenStack purge fails
    Then capi_janitor_cleanups_total{result="failure"} is incremented by 1
```

> Implemented: `CounterVec` exposed via `ctrlmetrics.Registry` (port 8080/metrics).
> `Metrics *Metrics` field is injectable on the reconciler (DI for tests).

#### US11.2 — Kubernetes Events

```gherkin
Feature: Kubernetes Events on OpenStackCluster
  Scenario: Successful purge → Normal "CleanupSucceeded" event
    Given a cluster being deleted
    When the OpenStack purge succeeds
    Then a Normal event with reason "CleanupSucceeded" is emitted on the OpenStackCluster

  Scenario: Failed purge → Warning "CleanupFailed" event
    Given a cluster being deleted
    When the OpenStack purge fails
    Then a Warning event with reason "CleanupFailed" and the error message is emitted
```

> Implemented: `record.EventRecorder` injectable on the reconciler; `SetupWithManager`
> auto-initialises via `mgr.GetEventRecorderFor("capi-janitor")` when nil.

---

### Epic 12 — Robustness

#### US12.1 — HTTP Client Timeout

```gherkin
Feature: HTTP Timeout on the OpenStack Client
  Scenario: Context cancelled before the call
    Given an already-cancelled context
    When Authenticate is called
    Then an error is returned immediately

  Scenario: Safety net on the http.Client
    Given no context with a deadline provided by the caller
    Then the http.Client has a Timeout of 30 seconds
    (prevents calls from blocking indefinitely when OpenStack is unreachable)
```

#### US12.2 — Cinder Service Legacy Aliases

```gherkin
Feature: Cinder Service Detection with Aliases
  Scenario: Catalog with "volumev3" (standard >= Stein)
    Given an OpenStack catalog with service type "volumev3"
    When the operator looks up the Cinder client
    Then the "volumev3" client is used

  Scenario: Catalog with "block-storage" only
    Given an OpenStack catalog without "volumev3" but with "block-storage"
    When the operator looks up the Cinder client
    Then the "block-storage" client is used

  Scenario: Catalog with "volume" only (legacy alias < Stein)
    Given an OpenStack catalog without "volumev3" or "block-storage" but with "volume"
    When the operator looks up the Cinder client
    Then the "volume" client is used

  Scenario: Catalog without a Cinder service
    Given a catalog without "volumev3", "block-storage", or "volume"
    When the operator looks up the Cinder client
    Then a CatalogError is raised with the appropriate message
```

---

## Actions

1. [x] Audit the existing code
2. [x] Write the agile roadmap (this document)
3. [x] Scaffold the Go project with kubebuilder
4. [x] Write Go tests (TDD) for each user story
5. [x] Implement the features in Go (108 tests)
6. [x] Migrate the Helm chart for the Go image
7. [x] Implement epics 11 (observability) and 12 (robustness)
8. [x] OCI build via Nix (without Flake) + CycloneDX SBOM (US10.3 — outside initial plan)

## Final Result

| Layer | Key Files |
|---|---|
| OpenStack client | `internal/openstack/cloud.go`, `resources.go`, `purge.go` |
| Controller | `internal/controller/openstackcluster_controller.go`, `metrics.go` |
| Config | `internal/controller/config.go` (env vars) |
| Tests | 108 tests (4 packages) |
| Packaging | `Dockerfile`, `nix/default.nix`, `nix/nixpkgs.nix` |
| Helm | `chart/` — Deployment, ClusterRole, RBAC, health probes |
| CI | `.github/workflows/build-push-artifacts.yaml` (Nix + skopeo + SBOM) |

## Implementation Order

```
Epic 1 (Auth) → Epic 2 (FIPs) → Epic 3 (LBs + PR #261)
→ Epic 4 (SGs) → Epic 5 (Volumes) → Epic 6 (Snapshots)
→ Epic 7 (AppCreds) → Epic 8 (Lifecycle K8s) → Epic 9 (Config)
→ Epic 10 (Packaging + Nix/SBOM) → Epic 11 (Observability)
→ Epic 12 (Robustness)
```
