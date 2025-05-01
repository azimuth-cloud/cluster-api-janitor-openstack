import base64
import yaml
import unittest
from unittest import mock

import easykube

from capi_janitor.openstack import operator
from capi_janitor.openstack import openstack


class TestOperator(unittest.IsolatedAsyncioTestCase):

    async def test_operator(self):
        mock_easykube = mock.AsyncMock(spec=easykube.AsyncClient)
        operator.ekclient = mock_easykube

        await operator.on_cleanup()

        mock_easykube.aclose.assert_awaited_once_with()

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

    @mock.patch.object(openstack.Cloud, "from_clouds")
    async def test_purge_openstack_resources_success(self, mock_from_clouds):
        # Mocking the cloud object and API clients
        mock_cloud = mock.AsyncMock()
        mock_networkapi = mock.AsyncMock()
        mock_lbapi = mock.AsyncMock()
        mock_volumeapi = mock.AsyncMock()
        mock_identityapi = mock.AsyncMock()

        # Mock the __aenter__ to return the mock_cloud when using the async context manager
        mock_cloud.__aenter__.return_value = mock_cloud
        mock_cloud.is_authenticated = True
        mock_cloud.current_user_id = "user"
        mock_cloud.api_client.return_value = mock_networkapi

        # Return mock clients for different services when requested
        mock_from_clouds.return_value = mock_cloud

        # Mocking the resources for Network, Load Balancer, and Volume APIs
        mock_networkapi.resource.side_effect = lambda resource: {
            "floatingips": mock.AsyncMock(),
            "security-groups": mock.AsyncMock(),
        }.get(resource, None)

        mock_lbapi.resource.side_effect = lambda resource: {
            "loadbalancers": mock.AsyncMock(),
        }.get(resource, None)

        mock_volumeapi.resource.side_effect = lambda resource: {
            "snapshots/detail": mock.AsyncMock(),
            "snapshots": mock.AsyncMock(),
            "volumes/detail": mock.AsyncMock(),
            "volumes": mock.AsyncMock(),
        }.get(resource, None)

        mock_identityapi.resource.side_effect = lambda resource: {
            "application_credentials": mock.AsyncMock(),
        }.get(resource, None)

        # Mock logger
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

        # Simulate the purge_openstack_resources method behavior
        await operator.purge_openstack_resources(
            logger,
            clouds_yaml_data,  # Pass the mock cloud config
            "openstack",
            None,
            "mycluster",
            True,
            False,
        )

        # Add assertions here based on expected behavior
        # Example: Check that the resources were interacted with
        mock_networkapi.resource.assert_any_call("floatingips")
        mock_lbapi.resource.assert_any_call("loadbalancers")
        mock_volumeapi.resource.assert_any_call("snapshots")
        mock_volumeapi.resource.assert_any_call("volumes")

        # Example: Validate if appcred deletion was attempted
        mock_identityapi.resource.assert_any_call("application_credentials")
