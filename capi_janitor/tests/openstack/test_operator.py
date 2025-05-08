import base64
import unittest
from unittest import mock
import yaml

import easykube
from easykube.rest.util import PropertyDict

from capi_janitor.openstack import operator, openstack
from capi_janitor.openstack.operator import OPENSTACK_USER_VOLUMES_RECLAIM_PROPERTY
from capi_janitor.openstack import openstack


# Helper to create an async iterable
def aiter(iterable):
    class AsyncIter:
        def __init__(self, it):
            self.it = iter(it)

        def __aiter__(self):
            return self

        async def __anext__(self):
            try:
                return next(self.it)
            except StopIteration:
                raise StopAsyncIteration

    return AsyncIter(iterable)


class TestOperator(unittest.IsolatedAsyncioTestCase):
    async def test_operator(self):
        mock_easykube = mock.AsyncMock(spec=easykube.AsyncClient)
        operator.ekclient = mock_easykube

        await operator.on_cleanup()  # type: ignore

        mock_easykube.aclose.assert_awaited_once_with()

    async def test_fips_for_cluster(self):
        fips = [
            mock.Mock(
                description="Floating IP for Kubernetes external service from cluster mycluster",
                id=1,
            ),
            mock.Mock(
                description="Floating IP for Kubernetes external service from cluster othercluster",
                id=2,
            ),
            mock.Mock(description="Some other description", id=3),
            mock.Mock(
                description="Floating IP for Kubernetes external service from cluster mycluster",
                id=4,
            ),
        ]

        resource_mock = mock.Mock()
        resource_mock.list = mock.AsyncMock(return_value=aiter(fips))

        result = []
        async for fip in operator.fips_for_cluster(resource_mock, "mycluster"):
            result.append(fip)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].id, 1)
        self.assertEqual(result[1].id, 4)

    async def test_lbs_for_cluster(self):
        lbs = [
            mock.Mock(name="lb1", id=1),
            mock.Mock(name="lb2", id=2),
            mock.Mock(name="lb3", id=3),
            mock.Mock(name="lb4", id=4),
        ]
        lbs[0].name = "kube_service_mycluster_api"
        lbs[1].name = "kube_service_othercluster_api"
        lbs[2].name = "fake_service_mycluster_api"
        lbs[3].name = "kube_service_mycluster_ui"

        resource_mock = mock.Mock()
        resource_mock.list = mock.AsyncMock(return_value=aiter(lbs))

        result = []
        async for lb in operator.lbs_for_cluster(resource_mock, "mycluster"):
            result.append(lb)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].id, 1)
        self.assertEqual(result[1].id, 4)

    async def test_secgroups_for_cluster(self):
        secgroups = [
            mock.Mock(
                description="Security Group for Service LoadBalancer in cluster mycluster",
                id=1,
            ),
            mock.Mock(
                description="Security Group for Service LoadBalancer in cluster othercluster",
                id=2,
            ),
            mock.Mock(description="Other description", id=3),
            mock.Mock(
                description="Security Group for Service LoadBalancer in cluster mycluster",
                id=4,
            ),
        ]

        resource_mock = mock.Mock()
        resource_mock.list = mock.AsyncMock(return_value=aiter(secgroups))

        result = []
        async for sg in operator.secgroups_for_cluster(resource_mock, "mycluster"):
            result.append(sg)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].id, 1)
        self.assertEqual(result[1].id, 4)

    async def test_volumes_and_snapshots_for_cluster(self):
        # Mock volumes with metadata containing the cluster owner information
        resources = [
            mock.Mock(id=1, metadata={"cinder.csi.openstack.org/cluster": "mycluster"}),
            mock.Mock(
                id=2, metadata={"cinder.csi.openstack.org/cluster": "othercluster"}
            ),
            mock.Mock(id=3, metadata={"cinder.csi.openstack.org/cluster": "mycluster"}),
            mock.Mock(
                id=4, metadata={"cinder.csi.openstack.org/cluster": "othercluster"}
            ),
            # Volumes with invalid metadata
            mock.Mock(id=5, metadata={"another_key": "value"}),
        ]

        resource_mock = mock.Mock()
        resource_mock.list = mock.AsyncMock(return_value=aiter(resources))

        volumes_result = []
        async for vol in operator.volumes_for_cluster(resource_mock, "mycluster"):
            volumes_result.append(vol)

        self.assertEqual(len(volumes_result), 2)
        self.assertEqual(volumes_result[0].id, 1)
        self.assertEqual(volumes_result[1].id, 3)

        # Reset mock values
        resource_mock.list = mock.AsyncMock(return_value=aiter(resources))

        snapshots_result = []
        async for vol in operator.snapshots_for_cluster(resource_mock, "mycluster"):
            snapshots_result.append(vol)

        self.assertEqual(len(snapshots_result), 2)
        self.assertEqual(snapshots_result[0].id, 1)
        self.assertEqual(snapshots_result[1].id, 3)

    async def test_empty_iterator(self):
        self.assertTrue(await operator.empty(aiter([])))

    async def test_non_empty_iterator(self):
        self.assertFalse(await operator.empty(aiter([1, 2, 3])))

    @mock.patch.object(operator, "patch_finalizers")
    @mock.patch.object(operator, "_get_os_cluster_client")
    async def test_on_openstackcluster_event_adds_finalizers(
        self, mock_get_client, mock_patch_finalizers
    ):
        logger = mock.Mock()
        mock_get_client.return_value = "mock_client"

        await operator._on_openstackcluster_event_impl(
            name="mycluster",
            namespace="default",
            meta={},
            labels={},
            spec={},
            logger=logger,
            body={},
        )

        mock_patch_finalizers.assert_awaited_once_with(
            "mock_client", "mycluster", "default", ["janitor.capi.stackhpc.com"]
        )
        logger.debug.assert_has_calls(
            [mock.call("cluster name that will be used for cleanup: 'mycluster'")]
        )
        logger.info.assert_has_calls([mock.call("added janitor finalizer to cluster")])

    @mock.patch.object(operator, "patch_finalizers")
    @mock.patch.object(operator, "_get_os_cluster_client")
    async def test_on_openstackcluster_event_skip_no_finalizers(
        self, mock_get_client, mock_patch_finalizers
    ):
        logger = mock.Mock()
        mock_get_client.return_value = "mock_client"

        await operator._on_openstackcluster_event_impl(
            name="mycluster",
            namespace="default",
            meta={"deletionTimestamp": "2023-10-01T00:00:00Z"},
            labels={},
            spec={},
            logger=logger,
            body={},
        )

        mock_patch_finalizers.assert_not_awaited()
        logger.debug.assert_has_calls(
            [mock.call("cluster name that will be used for cleanup: 'mycluster'")]
        )
        logger.info.assert_has_calls(
            [mock.call("janitor finalizer not present, skipping cleanup")]
        )

    @mock.patch.object(operator, "_delete_secret")
    @mock.patch.object(operator, "_get_clouds_secret")
    @mock.patch.object(operator, "purge_openstack_resources")
    @mock.patch.object(operator, "patch_finalizers")
    @mock.patch.object(operator, "_get_os_cluster_client")
    async def test_on_openstackcluster_event_calls_purge(
        self,
        mock_get_client,
        mock_patch_finalizers,
        mock_purge,
        mock_clouds_secret,
        mock_delete_secret,
    ):
        logger = mock.Mock()
        mock_get_client.return_value = "mock_client"
        mock_secret = mock.Mock()
        mock_clouds_secret.return_value = mock_secret
        clouds_yaml_data = {
            "openstack": {
                "auth": {
                    "auth_url": "https://example.com:5000/v3",
                    "username": "user",
                    "password": "pass",
                    "project_name": "project",
                    "user_domain_name": "Default",
                    "project_domain_name": "Default",
                }
            }
        }
        mock_secret.data = {
            "clouds.yaml": base64.b64encode(yaml.dump(clouds_yaml_data).encode("utf-8"))
        }
        mock_secret.metadata = {
            "annotations": {"janitor.capi.stackhpc.com/credential-policy": "delete"},
            "name": "appcred42",
        }

        await operator._on_openstackcluster_event_impl(
            name="mycluster",
            namespace="namespace1",
            meta={
                "deletionTimestamp": "2023-10-01T00:00:00Z",
                "finalizers": ["janitor.capi.stackhpc.com"],
                "annotations": {
                    "janitor.capi.stackhpc.com/volumes-policy": "delete",
                },
            },
            labels={},
            spec={"identityRef": {"name": "appcred42"}},
            logger=logger,
            body={},
        )

        mock_purge.assert_awaited_once_with(
            logger,
            clouds_yaml_data,
            "openstack",
            None,
            "mycluster",
            True,
            True,
        )
        mock_delete_secret.assert_awaited_once_with("appcred42", "namespace1")
        mock_patch_finalizers.assert_awaited_once_with(
            "mock_client", "mycluster", "namespace1", []
        )
        logger.debug.assert_has_calls(
            [mock.call("cluster name that will be used for cleanup: 'mycluster'")]
        )
        logger.info.assert_has_calls(
            [
                mock.call("cloud credential secret deleted"),
                mock.call("removed janitor finalizer from cluster"),
            ]
        )

    @mock.patch.object(openstack.Cloud, "from_clouds")
    async def test_purge_openstack_resources_raises(self, mock_from_clouds):

        mock_networkapi = mock.AsyncMock()
        mock_networkapi.resource.side_effect = lambda resource: resource

        mock_cloud = mock.AsyncMock()
        mock_cloud.__aenter__.return_value = mock_cloud
        mock_cloud.is_authenticated = False
        mock_cloud.current_user_id = "user"
        mock_cloud.api_client.return_value = mock_networkapi

        mock_from_clouds.return_value = mock_cloud

        logger = mock.Mock()
        clouds_yaml_data = {
            "clouds": {
                "openstack": {
                    "auth": {
                        "auth_url": "https://example.com:5000/v3",
                        "application_credential_id": "user",
                        "application_credential_secret": "pass",
                    },
                    "region_name": "RegionOne",
                    "interface": "public",
                    "identity_api_version": 3,
                    "auth_type": "v3applicationcredential",
                }
            }
        }
        with self.assertRaises(openstack.AuthenticationError) as e:
            await operator.purge_openstack_resources(
                logger,
                clouds_yaml_data,
                "openstack",
                None,
                "mycluster",
                True,
                False,
            )
        self.assertEqual(
            str(e.exception),
            "failed to authenticate as user: user",
        )

    # @mock.patch.object(openstack.Cloud, "from_clouds")
    # async def test_purge_openstack_resources_success(self, mock_from_clouds):
    #     # Mocking the cloud object and API clients
    #     mock_cloud = mock.AsyncMock()
    #     mock_networkapi = mock.AsyncMock()
    #     mock_lbapi = mock.AsyncMock()
    #     mock_volumeapi = mock.AsyncMock()
    #     mock_identityapi = mock.AsyncMock()

    #     # Mock the __aenter__ to return the mock_cloud when using the async context manager
    #     mock_cloud.__aenter__.return_value = mock_cloud
    #     mock_cloud.is_authenticated = True
    #     mock_cloud.current_user_id = "user"
    #     mock_cloud.api_client.return_value = mock_networkapi

    #     # Return mock clients for different services when requested
    #     mock_from_clouds.return_value = mock_cloud

    #     # Mocking the resources for Network, Load Balancer, and Volume APIs
    #     mock_networkapi.resource.side_effect = lambda resource: {
    #         "floatingips": mock.AsyncMock(),
    #         "security-groups": mock.AsyncMock(),
    #     }.get(resource, None)

    #     mock_lbapi.resource.side_effect = lambda resource: {
    #         "loadbalancers": mock.AsyncMock(),
    #     }.get(resource, None)

    #     mock_volumeapi.resource.side_effect = lambda resource: {
    #         "snapshots/detail": mock.AsyncMock(),
    #         "snapshots": mock.AsyncMock(),
    #         "volumes/detail": mock.AsyncMock(),
    #         "volumes": mock.AsyncMock(),
    #     }.get(resource, None)

    #     mock_identityapi.resource.side_effect = lambda resource: {
    #         "application_credentials": mock.AsyncMock(),
    #     }.get(resource, None)

    #     # Mock logger
    #     logger = mock.Mock()

    #     clouds_yaml_data = {
    #         "clouds": {
    #             "openstack": {
    #                 "auth": {
    #                     "auth_url": "https://example.com:5000/v3",
    #                     "application_credential_id": "user",
    #                     "application_credential_secret": "pass",
    #                 },
    #                 "region_name": "RegionOne",
    #                 "interface": "public",
    #                 "identity_api_version": 3,
    #                 "auth_type": "v3applicationcredential",
    #             }
    #         }
    #     }

    #     # Simulate the purge_openstack_resources method behavior
    #     await operator.purge_openstack_resources(
    #         logger,
    #         clouds_yaml_data,  # Pass the mock cloud config
    #         "openstack",
    #         None,
    #         "mycluster",
    #         True,
    #         False,
    #     )

    #     # Add assertions here based on expected behavior
    #     # Example: Check that the resources were interacted with
    #     mock_networkapi.resource.assert_any_call("floatingips")
    #     mock_lbapi.resource.assert_any_call("loadbalancers")
    #     mock_volumeapi.resource.assert_any_call("snapshots")
    #     mock_volumeapi.resource.assert_any_call("volumes")

    #     # Example: Validate if appcred deletion was attempted
    #     mock_identityapi.resource.assert_any_call("application_credentials")

    @mock.patch.object(openstack, "Resource")
    async def test_user_keep_volumes_filter(self, mock_volumes_resource):
        # Arrange
        async def _list_volumes():
            test_volumes = [
                {
                    "id": "123",
                    "name": "volume-1",
                    "metadata": {
                        "cinder.csi.openstack.org/cluster": "cluster-1",
                        OPENSTACK_USER_VOLUMES_RECLAIM_PROPERTY: "anything-but-true",
                    },
                },
                {
                    "id": "456",
                    "name": "volume-2",
                    "metadata": {
                        "cinder.csi.openstack.org/cluster": "cluster-1",
                        OPENSTACK_USER_VOLUMES_RECLAIM_PROPERTY: "true",
                    },
                },
                {
                    "id": "789",
                    "name": "volume-3",
                    "metadata": {
                        "cinder.csi.openstack.org/cluster": "cluster-2",
                        OPENSTACK_USER_VOLUMES_RECLAIM_PROPERTY: "true",
                    },
                },
            ]
            for volume in map(PropertyDict, test_volumes):
                yield volume

        mock_volumes_resource.list.return_value = _list_volumes()
        # Act
        filtered_volumes = [
            v
            async for v in operator.filtered_volumes_for_cluster(
                mock_volumes_resource, "cluster-1"
            )
        ]
        # Assert
        self.assertEqual(len(filtered_volumes), 1)
        self.assertEqual(filtered_volumes[0].get("name"), "volume-1")
