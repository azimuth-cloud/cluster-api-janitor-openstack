import unittest
from unittest import mock

import easykube

from capi_janitor.openstack import operator


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
