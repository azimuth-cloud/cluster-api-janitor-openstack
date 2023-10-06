import asyncio
import base64
import functools
import os
import random

import kopf
import yaml

import easykube

from . import openstack


ekconfig = easykube.Configuration.from_environment()
ekclient = ekconfig.async_client()


CAPO_API_GROUP = "infrastructure.cluster.x-k8s.io"
FINALIZER = "janitor.capi.stackhpc.com"

VOLUMES_ANNOTATION = "janitor.capi.stackhpc.com/volumes-policy"
VOLUMES_ANNOTATION_DELETE = "delete"
VOLUMES_ANNOTATION_DEFAULT = os.environ.get(
    "CAPI_JANITOR_DEFAULT_VOLUMES_POLICY",
    VOLUMES_ANNOTATION_DELETE
)

RETRY_ANNOTATION = "janitor.capi.stackhpc.com/retry"
RETRY_MAX_BACKOFF = int(os.environ.get("CAPI_JANITOR_RETRY_MAX_BACKOFF", "60"))


@kopf.on.cleanup()
async def on_cleanup(**kwargs):
    """
    Runs on operator shutdown.
    """
    # Make sure that the easykube client is shut down properly
    await ekclient.aclose()


class ResourcesStillPresentError(Exception):
    """
    Raised when cluster resources are still present even after being deleted,
    e.g. while waiting for deletion.
    """
    def __init__(self, resource, cluster):
        super().__init__(f"{resource} still present for cluster {cluster}")


async def fips_for_cluster(resource, cluster):
    """
    Async iterator for FIPs belonging to the specified cluster.
    """
    async for fip in resource.list():
        if not fip.description.startswith("Floating IP for Kubernetes external service"):
            continue
        if not fip.description.endswith(f"from cluster {cluster}"):
            continue
        yield fip


async def lbs_for_cluster(resource, cluster):
    """
    Async iterator for loadbalancers belonging to the specified cluster.
    """
    async for lb in resource.list():
        if lb.name.startswith(f"kube_service_{cluster}_"):
            yield lb


async def volumes_for_cluster(resource, cluster):
    """
    Async iterator for volumes belonging to the specified cluster.
    """
    async for vol in resource.list():
        # CSI Cinder sets metadata on the volumes that we can look for
        owner = vol.metadata.get("cinder.csi.openstack.org/cluster")
        if owner and owner == cluster:
            yield vol


async def empty(async_iterator):
    """
    Returns True if the given async iterator is empty, False otherwise.
    """
    try:
        _ = await async_iterator.__anext__()
    except StopAsyncIteration:
        return True
    else:
        return False


async def patch_finalizers(resource, name, namespace, finalizers):
    """
    Patches the finalizers of a resource. If the resource does not exist any
    more, that is classed as a success.
    """
    try:
        await resource.patch(
            name,
            { "metadata": { "finalizers": finalizers } },
            namespace = namespace
        )
    except easykube.ApiError as exc:
        if exc.status_code != 404:
            raise
    

def retry_event(handler):
    """
    Decorator for retrying events on Kubernetes objects.

    Objects are annotated with the number of times the handler has been retried
    since it was last successful, which is used to calculate an exponential backoff.

    Doing it this way ensures that the handler sees the most recent data each time.

    As recommended in the kopf docs, handlers should be idempotent as this mechanism
    may result in the handler being called twice if an update happens between a failure
    and the associated retry.
    """
    @functools.wraps(handler)
    async def wrapper(**kwargs):
        body = kwargs["body"]
        resource = await ekclient.api(body["apiVersion"]).resource(body["kind"])
        try:
            result = await handler(**kwargs)
        except Exception as exc:
            kwargs["logger"].exception(str(exc))
            # Check to see how many times a handler has been retried
            retries = int(kwargs["annotations"].get(RETRY_ANNOTATION, "0"))
            # Calculate the backoff
            backoff = 2**retries + random.uniform(0, 1)
            clamped_backoff = min(backoff, RETRY_MAX_BACKOFF)
            # Wait for the backoff before annotating the resource
            await asyncio.sleep(clamped_backoff)
            try:
                await resource.patch(
                    kwargs["name"],
                    {
                        "metadata": {
                            "annotations": {
                                RETRY_ANNOTATION: str(retries + 1),
                            }
                        }
                    },
                    namespace = kwargs["namespace"]
                )
            except easykube.ApiError as exc:
                if exc.status_code != 404:
                    raise
        else:
            if RETRY_ANNOTATION in kwargs["annotations"]:
                # If the handler completes successfully, ensure the annotation is removed
                # The forward slash in the annotation is designated by '~1' in JSON patch
                annotation = RETRY_ANNOTATION.replace('/', '~1')
                try:
                    await resource.json_patch(
                        kwargs["name"],
                        [
                            {
                                "op": "remove",
                                "path": f"/metadata/annotations/{annotation}",
                            },
                        ],
                        namespace = kwargs["namespace"]
                    )
                except easykube.ApiError as exc:
                    if exc.status_code != 404:
                        raise
            return result
    return wrapper


@kopf.on.event(CAPO_API_GROUP, "openstackclusters")
@retry_event
async def on_openstackcluster_event(type, name, namespace, meta, spec, **kwargs):
    """
    Executes whenever an event occurs for an OpenStack cluster.
    """
    # Get the resource for manipulating OpenStackClusters at the preferred version
    capoapi = await ekclient.api_preferred_version(CAPO_API_GROUP)
    openstackclusters = await capoapi.resource("openstackclusters")

    finalizers = meta.get("finalizers", [])
    # We add a custom finalizer to OpenStack cluster objects to
    # prevent them from being deleted until we have acted
    if not meta.get("deletionTimestamp"):
        if FINALIZER not in finalizers:
            await patch_finalizers(
                openstackclusters,
                name,
                namespace,
                finalizers + [FINALIZER]
            )
        return
    
    # If we are being deleted but the finalizer has already been removed,
    # then there is nothing to do
    if FINALIZER not in finalizers:
        return
    
    # Get the cloud credential from the cluster
    secrets = await ekclient.api("v1").resource("secrets")
    clouds_secret = await secrets.fetch(spec["identityRef"]["name"], namespace = namespace)
    clouds = yaml.safe_load(base64.b64decode(clouds_secret.data["clouds.yaml"]))
    if "cacert" in clouds_secret.data:
        cacert = base64.b64decode(clouds_secret.data["cacert"]).decode()
    else:
        cacert = None

    # Use the credential to delete external resources as required
    async with openstack.Cloud.from_clouds(clouds, cacert = cacert) as cloud:
        # Release any floating IPs associated with loadbalancer services for the cluster
        networkapi = cloud.api_client("network", "/v2.0/")
        fips = networkapi.resource("floatingips")
        check_fips = True
        async for fip in fips_for_cluster(fips, name):
            await fips.delete(fip.id)
        else:
            check_fips = False

        # Delete any loadbalancers associated with loadbalancer services for the cluster
        lbapi = cloud.api_client("load-balancer", "/v2/lbaas/")
        loadbalancers = lbapi.resource("loadbalancers")
        check_lbs = True
        async for lb in lbs_for_cluster(loadbalancers, name):
            if lb.provisioning_status not in {"PENDING_DELETE", "DELETED"}:
                await loadbalancers.delete(lb.id, cascade = "true")
        else:
            check_lbs = False

        # Delete volumes associated with PVCs, unless requested otherwise via the annotation
        volumeapi = cloud.api_client("volumev3")
        volumes_detail = volumeapi.resource("volumes/detail")
        volumes = volumeapi.resource("volumes")
        check_volumes = False
        volumes_annotation_value = meta.get("annotations", {}).get(
            VOLUMES_ANNOTATION,
            VOLUMES_ANNOTATION_DEFAULT
        )
        if volumes_annotation_value == VOLUMES_ANNOTATION_DELETE:
            check_volumes = True
            async for vol in volumes_for_cluster(volumes_detail, name):
                if vol.status != "deleting":
                    await volumes.delete(vol.id)
            else:
                check_volumes = False

        # Check that the resources have actually been deleted
        if check_fips and not await empty(fips_for_cluster(fips, name)):
            raise ResourcesStillPresentError("floatingips", name)
        if check_lbs and not await empty(lbs_for_cluster(loadbalancers, name)):
            raise ResourcesStillPresentError("loadbalancers", name)
        if check_volumes and not await empty(volumes_for_cluster(volumes_detail, name)):
            raise ResourcesStillPresentError("volumes", name)
        
    # If we get to here, we can remove the finalizer
    await patch_finalizers(
        openstackclusters,
        name,
        namespace,
        [f for f in finalizers if f != FINALIZER]
    )
