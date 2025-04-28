import unittest
from unittest import mock

import easykube

from capi_janitor.openstack import operator


class TestOperator(unittest.IsolatedAsyncioTestCase):

    @mock.patch.object(easykube.AsyncClient, "aclose")
    async def test_operator(self, mock_aclose):
        await operator.on_cleanup()
        mock_aclose.assert_awaited_once()
