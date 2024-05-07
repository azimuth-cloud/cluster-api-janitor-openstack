import asyncio
import base64
import functools
import os
import random

import kopf
import yaml

import easykube
import httpx

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

CREDENTIAL_ANNOTATION = "janitor.capi.stackhpc.com/credential-policy"
CREDENTIAL_ANNOTATION_DELETE = "delete"

RETRY_ANNOTATION = "janitor.capi.stackhpc.com/retries"
RETRY_MAX_BACKOFF = int(os.environ.get("CAPI_JANITOR_RETRY_MAX_BACKOFF", "60"))


@kopf.on.cleanup()
async def on_cleanup(**kwargs):
    """
    Runs on operator shutdown.
    """
    # Make sure that the easykube client is shut down properly
    await ekclient.aclose()


class FinalizerStillPresentError(Exception):
    """
    Raised when a finalizer from another controller is preventing us from deleting an appcred.
    """
    def __init__(self, finalizer, cluster):
        super().__init__(f"finalizer '{finalizer}' still present for cluster {cluster}")


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


async def snapshots_for_cluster(resource, cluster):
    """
    Async iterator for snapshots belonging to the specified cluster.
    """
    async for snapshot in resource.list():
        # CSI Cinder sets metadata on the volumes that we can look for
        owner = snapshot.metadata.get("cinder.csi.openstack.org/cluster")
        if owner and owner == cluster:
            yield snapshot


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


async def try_delete(logger, resource, instances, **kwargs):
    """
    Tries to delete the specified instances, catching 400 and 409 exceptions for retry.

    It returns a boolean indicating whether a check is required for the resource.
    """
    check_required = False
    async for instance in instances:
        check_required = True
        try:
            await resource.delete(instance.id, **kwargs)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in {400, 409}:
                logger.warn(
                    f"got status code {exc.response.status_code} when attempting to delete "
                    f"{resource.singular_name} with ID {instance.id} - will retry"
                )
            else:
                raise
    return check_required


async def purge_openstack_resources(
    logger,
    clouds,
    cloud_name,
    cacert,
    name,
    include_volumes,
    include_appcred
):
    """
    Cleans up the OpenStack resources created by the OCCM and CSI for a cluster.
    """
    # Use the credential to delete external resources as required
    async with openstack.Cloud.from_clouds(clouds, cloud_name, cacert) as cloud:
        # If the session is not authenticated, there is nothing we can do
        if not cloud.is_authenticated:
            logger.warn("application credential has been deleted")
            return

        # Release any floating IPs associated with loadbalancer services for the cluster
        networkapi = cloud.api_client("network", "/v2.0/")
        fips = networkapi.resource("floatingips")
        check_fips = await try_delete(logger, fips, fips_for_cluster(fips, name))
        logger.info("deleted floating IPs for LoadBalancer services")

        # Delete any loadbalancers associated with loadbalancer services for the cluster
        lbapi = cloud.api_client("load-balancer", "/v2/lbaas/")
        loadbalancers = lbapi.resource("loadbalancers")
        check_lbs = await try_delete(
            logger,
            loadbalancers,
            lbs_for_cluster(loadbalancers, name),
            cascade = "true"
        )
        logger.info("deleted load balancers for LoadBalancer services")

        # Delete volumes and snapshots associated with PVCs, unless requested
        # otherwise via the annotation
        volumeapi = cloud.api_client("volumev3")
        snapshots_detail = volumeapi.resource("snapshots/detail")
        snapshots = volumeapi.resource("snapshots")
        check_snapshots = False
        volumes_detail = volumeapi.resource("volumes/detail")
        volumes = volumeapi.resource("volumes")
        check_volumes = False
        if include_volumes:
            check_snapshots = await try_delete(
                logger,
                snapshots,
                snapshots_for_cluster(snapshots_detail, name)
            )
            logger.info("deleted snapshots for persistent volume claims")
            check_volumes = await try_delete(
                logger,
                volumes,
                volumes_for_cluster(volumes_detail, name)
            )
            logger.info("deleted volumes for persistent volume claims")

        # Check that the resources have actually been deleted
        if check_fips and not await empty(fips_for_cluster(fips, name)):
            raise ResourcesStillPresentError("floatingips", name)
        if check_lbs and not await empty(lbs_for_cluster(loadbalancers, name)):
            raise ResourcesStillPresentError("loadbalancers", name)
        if check_volumes and not await empty(volumes_for_cluster(volumes_detail, name)):
            raise ResourcesStillPresentError("volumes", name)
        if check_snapshots and not await empty(snapshots_for_cluster(snapshots_detail, name)):
            raise ResourcesStillPresentError("snapshots", name)

        # Now we have finished deleting resources, try to delete the appcred itself
        # This requires an appcred to be unrestricted
        # If it is not, we proceed but emit a warning
        if include_appcred:
            identityapi = cloud.api_client("identity", "v3")
            appcreds = identityapi.resource(
                "application_credentials",
                # appcreds are user-namespaced
                prefix = f"users/{cloud.current_user_id}"
            )
            appcred_id = clouds["clouds"]["openstack"]["auth"]["application_credential_id"]
            try:
                await appcreds.delete(appcred_id)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 403:
                    logger.warn("unable to delete application credential for cluster")
                else:
                    raise
            logger.info("deleted application credential for cluster")


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
        # Patching the finalizers can result in a 422 if we are deleting and CAPO
        # has removed its finalizer while we were working
        if exc.status_code == 422:
            raise kopf.TemporaryError("error patching finalizers", delay = 1)
        elif exc.status_code != 404:
            raise


def retry_event(handler):
    """
    Decorator for retrying events on Kubernetes objects.

    Instead of retrying within the handler, potentially on stale data, the object is
    annotated with the number of times it has been retried. This triggers a new event
    for the retry which contains up-to-date data.

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
            # Check to see how many times a handler has been retried
            retries = int(kwargs["annotations"].get(RETRY_ANNOTATION, "0"))
            if isinstance(exc, kopf.TemporaryError):
                kwargs["logger"].warn(str(exc))
                backoff = exc.delay
            elif isinstance(exc, (FinalizerStillPresentError, ResourcesStillPresentError)):
                kwargs["logger"].warn(str(exc))
                backoff = 5
            else:
                kwargs["logger"].exception(str(exc))
                # Calculate the backoff
                backoff = min(2**retries + random.uniform(0, 1), RETRY_MAX_BACKOFF)
            # Wait for the backoff before annotating the resource
            await asyncio.sleep(backoff)
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
async def on_openstackcluster_event(name, namespace, meta, spec, logger, **kwargs):
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
            logger.info("added janitor finalizer to cluster")
        return
    
    # NOTE: If we get to here, the cluster is deleting

    # If our finalizer is not present, we don't do anything
    if FINALIZER not in finalizers:
        return

    # Get the cloud credential from the cluster and use it to delete dangling
    # resources created by OpenStack integrations on the cluster
    secrets = await ekclient.api("v1").resource("secrets")
    try:
        clouds_secret = await secrets.fetch(spec["identityRef"]["name"], namespace = namespace)
    except easykube.ApiError as exc:
        if exc.status_code != 404:
            raise
    else:
        clouds = yaml.safe_load(base64.b64decode(clouds_secret.data["clouds.yaml"]))
        if "cacert" in clouds_secret.data:
            cacert = base64.b64decode(clouds_secret.data["cacert"]).decode()
        else:
            cacert = None
        # The cloud name comes from spec.identityRef.cloudName from v1beta1 onwards
        # Prior to that, it comes from spec.cloudName
        cloud_name = spec["identityRef"].get("cloudName", spec.get("cloudName", "openstack"))
        # The value of this annotation on the cluster decides whether to delete volumes
        volumes_annotation_value = meta.get("annotations", {}).get(
            VOLUMES_ANNOTATION,
            VOLUMES_ANNOTATION_DEFAULT
        )
        # We want to remove the appcred iff:
        #
        #   1. The annotation on the secret is present and says delete
        #   2. Our finalizer is the last finalizer
        #
        # This is because we need to allow CAPO to finish its work before we remove the
        # appcred + secret, but we do need to act to remove other resources that might
        # block CAPO from completing
        credential_annotation_value = clouds_secret.metadata.get("annotations", {}).get(
            CREDENTIAL_ANNOTATION
        )
        remove_appcred = credential_annotation_value == CREDENTIAL_ANNOTATION_DELETE
        await purge_openstack_resources(
            logger,
            clouds,
            cloud_name,
            cacert,
            name,
            volumes_annotation_value == VOLUMES_ANNOTATION_DELETE,
            remove_appcred and len(finalizers) == 1
        )
        # If we get to here, OpenStack resources have been successfully deleted
        # So we can remove the appcred secret if we are the last actor
        if remove_appcred and len(finalizers) == 1:
            await secrets.delete(clouds_secret.metadata.name, namespace = namespace)
            logger.info("cloud credential secret deleted")
        elif remove_appcred:
            # If the annotation says delete but other controllers are still acting, go round again
            raise FinalizerStillPresentError(next(f for f in finalizers if f != FINALIZER), name)

    # If we get to here, we can remove the finalizer
    await patch_finalizers(
        openstackclusters,
        name,
        namespace,
        [f for f in finalizers if f != FINALIZER]
    )
    logger.info("removed janitor finalizer from cluster")
