import base64
import yaml
import unittest
from unittest import mock

import easykube
from easykube.rest.util import PropertyDict

from capi_janitor.openstack import operator, openstack
from capi_janitor.openstack.operator import OPENSTACK_USER_VOLUMES_RECLAIM_PROPERTY


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
                        OPENSTACK_USER_VOLUMES_RECLAIM_PROPERTY: "true"
                    },
                },
                {
                    "id": "789",
                    "name": "volume-3",
                    "metadata": {
                        "cinder.csi.openstack.org/cluster": "cluster-2",
                        OPENSTACK_USER_VOLUMES_RECLAIM_PROPERTY: "true"
                    },
                },
            ]
            for volume in map(PropertyDict, test_volumes):
                yield volume

        mock_volumes_resource.list.return_value = _list_volumes()
        # Act
        filtered_volumes = [v async for v in  operator.filtered_volumes_for_cluster(mock_volumes_resource, "cluster-1")]
        # Assert
        self.assertEqual(len(filtered_volumes), 1)
        self.assertEqual(filtered_volumes[0].get("name"), "volume-1")
