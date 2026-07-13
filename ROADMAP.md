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

  Scenario: Token response is not valid JSON
    Given Keystone returns HTTP 201 with a malformed JSON body
    When the operator requests a token
    Then an error is returned
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

  Scenario: No interface configured
    Given a clouds.yaml entry without an "interface" value
    When the catalog is loaded
    Then the "public" interface is used by default

  Scenario: Catalog request fails with a non-404 error
    Given the catalog endpoint returns HTTP 500
    When the operator loads the catalog
    Then an error is returned

  Scenario: Catalog response is not valid JSON
    Given the catalog endpoint returns a malformed JSON body
    When the operator loads the catalog
    Then an error is returned
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

  Scenario: CA certificate content is not valid PEM
    Given a Kubernetes secret with a "cacert" entry that is not valid PEM data
    When the operator initialises the TLS transport
    Then an error is returned
```

#### US1.5 — Authentication via Username/Password (v3password)

```gherkin
Feature: OpenStack Authentication via Username/Password
  In order to support clouds that do not use application credentials
  As an operator
  I want to authenticate using a v3password auth block with the correct Keystone scope

  Scenario: Project-scoped request with a project ID
    Given a clouds.yaml auth block with "project_id" set
    When the token request body is built
    Then the request is scoped to that project by ID

  Scenario: Project-scoped request with a project name and explicit project domain
    Given a clouds.yaml auth block with "project_name" and "project_domain_id" (or "project_domain_name") set
    When the token request body is built
    Then the request is scoped to that project by name, with the given domain

  Scenario: Project-scoped request falls back to the user domain
    Given a clouds.yaml auth block with "project_name" set but no project domain
    And "user_domain_id" or "user_domain_name" is set
    When the token request body is built
    Then the project scope's domain falls back to the user domain

  Scenario: Project name with no domain information at all
    Given a clouds.yaml auth block with only "project_name" set
    When the token request body is built
    Then the project scope omits the domain key entirely

  Scenario: Domain-scoped request
    Given a clouds.yaml auth block with "domain_id" or "domain_name" set and no project
    When the token request body is built
    Then the request is scoped to that domain

  Scenario: No scoping information at all
    Given a clouds.yaml auth block with no project or domain fields
    When the token request body is built
    Then no "scope" key is included in the request

  Scenario: User identified by user_id
    Given a clouds.yaml auth block with "user_id" set
    When the token request body is built
    Then the user is identified by ID, and the "name"/domain fields are omitted

  Scenario: Username without any user domain
    Given a clouds.yaml auth block with "username" set and no user domain fields
    When the token request body is built
    Then the user block omits the domain key entirely
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

  Scenario: Floating IP already deleted
    Given a FIP deletion returns HTTP 404
    When the purge attempts to delete the FIP
    Then the deletion is treated as successful, not as an error
```

> Deletion verification for FIPs, LBs, security groups, volumes and snapshots
> (Epics 2 to 6) shares a common polling mechanism: verify immediately after
> issuing the deletes, then retry a bounded number of times with a fixed
> delay between attempts if the resource is still listed. This absorbs
> OpenStack's eventual consistency (`PENDING_DELETE` states) without
> incurring a wait when nothing needs one.

#### US2.3 — Defensive Pagination Parsing

```gherkin
Feature: Paginated Listing Robustness
  In order to avoid crashing on unexpected OpenStack API responses
  As an operator
  I want paginated list requests to degrade gracefully on malformed data

  Scenario: Malformed top-level JSON in a list page
    Given an OpenStack list endpoint returns a body that is not valid JSON
    When the page is parsed
    Then an error is returned

  Scenario: Pagination links field absent
    Given a list response without a "<resource>_links" field
    When the next page URL is resolved
    Then pagination stops after the current page (no error)

  Scenario: Pagination links field malformed
    Given a "<resource>_links" field that is not an array of link objects
    When the next page URL is resolved
    Then pagination stops after the current page (no error)

  Scenario: No "next" relation present
    Given a "<resource>_links" array without a "next" entry
    When the next page URL is resolved
    Then pagination stops after the current page (no error)
```

> `nextPageURL` and `listPages` are shared by FIPs, load balancers and
> security groups; the scenarios above were validated against the FIP
> listing endpoint but apply identically to the other two.

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

#### US5.3 — Defensive Handling of Malformed Cinder Responses

```gherkin
Feature: Cinder Response Robustness
  Scenario: Top-level volume/snapshot list response is not valid JSON
    Given the Cinder API returns a malformed JSON body for a list request
    When the volumes or snapshots of a cluster are listed
    Then an error is returned

  Scenario: "volumes"/"snapshots" key is not an array
    Given the Cinder API returns a list response where the items key is not an array
    When the volumes or snapshots of a cluster are listed
    Then an error is returned
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
    Then the credential secret is not deleted
    And the janitor finalizer is not removed
    And a retry annotation is set to trigger a later reconcile

  Scenario: Application Credential cannot be deleted (403)
    Given the Application Credential is restricted (no unrestricted flag)
    When the appcred deletion is attempted
    Then a warning is emitted
    And the Kubernetes secret deletion proceeds anyway

  Scenario: clouds.yaml cannot be parsed while resolving the credential ID
    Given a malformed clouds.yaml
    When the application credential ID is extracted for deletion
    Then an error is returned
```

#### US7.2 — Purge Orchestration Across Resource Types

```gherkin
Feature: OpenStack Resource Purge Orchestration
  In order to guarantee a consistent, predictable cleanup sequence
  As an operator
  I want resource types to be purged in a fixed order, stopping on the first failure

  Scenario: Authentication fails
    Given an invalid clouds.yaml
    When the purge is triggered
    Then the authentication error is returned immediately and no resources are touched

  Scenario: Floating IP deletion fails
    Given the Floating IP listing or deletion fails
    When the purge is triggered
    Then the error is returned immediately
    And load balancers, security groups, volumes and the application credential are not touched

  Scenario: Volume deletion fails
    Given include_volumes is true and volume listing or deletion fails
    When the purge is triggered
    Then the error is returned immediately
    And the application credential is not deleted, even if include_appcred is true

  Scenario: Volumes policy disabled
    Given include_volumes is false
    When the purge is triggered
    Then snapshots and volumes are not listed or deleted

  Scenario: Application credential deletion requested
    Given include_appcred is true and all prior steps succeed
    When the purge is triggered
    Then the application credential is deleted via the Identity API

  Scenario: Full successful purge
    Given include_volumes and include_appcred set as configured, and no step fails
    When the purge is triggered
    Then all resource types are processed in order and no error is returned
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

#### US8.5 — Robust Reconcile Error Handling

```gherkin
Feature: Reconcile Resilience to Kubernetes API Errors
  In order to avoid silently losing track of clusters
  As an operator
  I want Kubernetes API errors during reconciliation to be surfaced or handled explicitly

  Scenario: Fetching the OpenStackCluster fails with a non-NotFound error
    Given the Kubernetes API returns an error other than NotFound when fetching the cluster
    When Reconcile runs
    Then the error is propagated

  Scenario: Adding the finalizer fails
    Given the update to the OpenStackCluster fails
    When Reconcile attempts to add the janitor finalizer
    Then the error is propagated, wrapped as "adding finalizer"

  Scenario: Fetching the identity secret fails with a non-NotFound error
    Given the Kubernetes API returns an error other than NotFound when fetching the credential secret
    When Reconcile runs during deletion
    Then the error is propagated, wrapped as "fetching identity secret"

  Scenario: Identity secret does not exist
    Given the secret referenced by spec.identityRef does not exist
    When Reconcile runs during deletion
    Then Reconcile returns without error and does not attempt a purge

  Scenario: CloudName not specified
    Given spec.identityRef.cloudName is empty
    When Reconcile runs during deletion
    Then the cloud name "openstack" is used to authenticate

  Scenario: Retry annotation patch fails with a non-NotFound error
    Given a purge failure followed by a failure to patch the retry annotation
    When Reconcile handles the purge error
    Then the error is propagated

  Scenario: Deleting the credential secret fails with a non-NotFound error
    Given credential-policy is "delete", this is the last finalizer, and the secret deletion fails
    When Reconcile completes a successful purge
    Then the error is propagated, wrapped as "deleting credential secret"

  Scenario: Removing the finalizer fails
    Given a successful purge and no pending credential-policy deletion
    When Reconcile attempts to remove the janitor finalizer
    Then the error is propagated, wrapped as "removing finalizer"

  Scenario: No PurgeFunc configured
    Given the reconciler has no injected PurgeFunc
    When Reconcile triggers a purge
    Then the real openstack.PurgeResources implementation is used
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

#### US10.1 — Secure Image (Nix Build)

```gherkin
Feature: Secure OCI Image for the Go Operator
  Scenario: Reproducible Nix build
    Given the Go operator source code
    When `nix-build nix -A image` is run
    Then the manager binary is built with buildGoModule and CGO_ENABLED=0
    And the image contains only the Nix closure required to run the binary

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

#### US12.3 — Transient Error Classification

```gherkin
Feature: Distinguishing Transient from Fatal Deletion Errors
  Scenario: Non-HTTP error is never treated as transient
    Given a deletion attempt fails with an error that is not an HTTP status error (e.g. a network-level failure)
    When the operator classifies the error
    Then it is not treated as transient (only HTTP 400/409 are)
```

#### US12.4 — HTTP Response Body Read Failures

```gherkin
Feature: Robustness to Interrupted HTTP Responses
  Scenario: Response body cannot be fully read
    Given an OpenStack API call returns a successful status code
    And the response body fails while being read (e.g. connection interrupted mid-transfer)
    When the operator processes the response
    Then an error is returned
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
9. [x] Raise `internal/` test coverage from 77.5% to 93.0% (53 new tests — see Test Coverage below)

## Final Result

| Layer | Key Files |
|---|---|
| OpenStack client | `internal/openstack/cloud.go`, `resources.go`, `purge.go` |
| Controller | `internal/controller/openstackcluster_controller.go`, `metrics.go` |
| Config | `internal/controller/config.go` (env vars) |
| Tests | 168 tests (4 packages) |
| Packaging | `nix/default.nix`, `nix/nixpkgs.nix` |
| Helm | `chart/` — Deployment, ClusterRole, RBAC, health probes |
| CI | `.github/workflows/build-push-artifacts.yaml` (Nix + skopeo + SBOM) |

### Test Coverage (`internal/`)

| Metric | Before | After |
|---|---|---|
| Coverage (statements) | 77.5% | 93.0% |
| Tests | 115 | 168 |

New tests added (53), targeting the functions that were at 0% or had untested
error branches:

| Function(s) | Coverage before → after | File |
|---|---|---|
| `PurgeResources` | 0% → 82.6% | `internal/openstack/purge_test.go` (new) — 8 tests via a combined self-referential mock server (network/load-balancer/volumev3/identity) |
| `Reconcile` | 69% → 98.3% | `internal/controller/openstackcluster_controller_test.go` — 11 tests: Get/Update/Patch/Delete error injection via `interceptor.Funcs`, credential-policy branches (last finalizer vs. others still present), cloud name default, nil-`PurgeFunc` fallback |
| `otherFinalizer` | 0% → 100% | `internal/controller/internal_test.go` (new, white-box) |
| `deleteSecret`, `getSecret` | 0% / 50% → 100% | covered indirectly through the `Reconcile` tests above |
| `httpStatusError.Error/StatusCode`, `isTransient`, `AppCredentialID`, `passwordScope`, `passwordTokenBody`, `loadCACert` | various → 100% | `internal/openstack/cloud_test.go` |
| `doDelete` (404 path), `nextPageURL` (pagination edge cases), `listVolumeItems` (malformed JSON) | various → 100% or near | `internal/openstack/resources_test.go` |
| `isTransient` (non-HTTP error), `doGet` (body-read error) | → 100% / 81.8% | `internal/openstack/internal_test.go` (new, white-box) |

Residual gaps accepted as out of scope (negligible risk vs. setup/runtime cost):
`SetupWithManager` (pure `ctrl.Manager` wiring), the real `time.Sleep`
fallbacks in `Session.sleep` / `OpenStackClusterReconciler.sleep`, the
`x509.SystemCertPool()` OS-level error path in `loadCACert`, and the
malformed-URL branch of `newDeleteRequest`.

The corresponding use cases were written up as Gherkin scenarios and folded
into the relevant epics above: US1.2 (catalog defaults/errors), US1.4 (CA
cert), new US1.5 (password auth & scope), US2.2/new US2.3 (FIP 404 handling,
pagination robustness), new US5.3 (Cinder response robustness), US7.1/new
US7.2 (appcred edge cases, purge orchestration), new US8.5 (Reconcile error
handling), new US12.3/US12.4 (transient error classification, body-read
failures).

## Implementation Order

```
Epic 1 (Auth) → Epic 2 (FIPs) → Epic 3 (LBs + PR #261)
→ Epic 4 (SGs) → Epic 5 (Volumes) → Epic 6 (Snapshots)
→ Epic 7 (AppCreds) → Epic 8 (Lifecycle K8s) → Epic 9 (Config)
→ Epic 10 (Packaging + Nix/SBOM) → Epic 11 (Observability)
→ Epic 12 (Robustness)
```
