import unittest
from unittest import mock

import easykube

from capi_janitor.openstack import operator


class TestOperator(unittest.IsolatedAsyncioTestCase):

    async def test_operator(self):
        mock_easykube = mock.AsyncMock(spec=easykube.AsyncClient)
        operator.ekclient = mock_easykube

        await operator.on_cleanup()

        mock_easykube.aclose.assert_awaited_once()
