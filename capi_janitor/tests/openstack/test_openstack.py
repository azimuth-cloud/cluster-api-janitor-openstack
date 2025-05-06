import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from capi_janitor.openstack.openstack import Cloud, Client, AuthenticationError


class TestCloudAenter(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.auth = MagicMock()
        self.transport = AsyncMock()
        self.interface = "public"
        self.region = "region1"
        self.cloud = Cloud(self.auth, self.transport, self.interface, self.region)

    @patch("capi_janitor.openstack.openstack.Client")
    async def test_aenter_successful_authentication(self, mock_client):
        mock_client_instance = AsyncMock()
        mock_client.return_value = mock_client_instance
        mock_client_instance.get.return_value.json = MagicMock(
            return_value={
                "catalog": [
                    {
                        "type": "compute",
                        "endpoints": [
                            {
                                "interface": "public",
                                "region_id": "region1",
                                "url": "https://compute.example.com",
                            }
                        ],
                    }
                ]
            }
        )
        mock_client_instance._base_url = "https://compute.example.com"

        async with self.cloud as cloud:
            self.assertTrue(cloud.is_authenticated)
            self.assertIn("compute", cloud.apis)
            self.assertEqual(
                cloud.api_client("compute")._base_url, "https://compute.example.com"
            )

    @patch("capi_janitor.openstack.openstack.Client")
    async def test_aenter_authentication_failure(self, mock_client):
        mock_client_instance = AsyncMock()
        mock_client.return_value = mock_client_instance
        mock_client_instance.get.side_effect = AuthenticationError("test_user")

        with self.assertRaises(AuthenticationError):
            async with self.cloud:
                pass

    @patch("capi_janitor.openstack.openstack.Client")
    async def test_aenter_404_error(self, mock_client):
        mock_client_instance = AsyncMock()
        mock_client.return_value = mock_client_instance
        mock_client_instance.get.side_effect = MagicMock(
            response=MagicMock(status_code=404)
        )

        async with self.cloud as cloud:
            self.assertFalse(cloud.is_authenticated)

    @patch("capi_janitor.openstack.openstack.Client")
    async def test_aenter_no_matching_interface(self, mock_client):
        mock_client_instance = AsyncMock()
        mock_client.return_value = mock_client_instance
        mock_client_instance.get.return_value.json = MagicMock(
            return_value={
                "catalog": [
                    {
                        "type": "compute",
                        "endpoints": [
                            {
                                "interface": "internal",
                                "region_id": "region1",
                                "url": "https://compute.example.com",
                            }
                        ],
                    }
                ]
            }
        )

        async with self.cloud as cloud:
            self.assertFalse(cloud.is_authenticated)
            self.assertEqual(cloud.apis, [])

    @patch("capi_janitor.openstack.openstack.Client")
    async def test_aenter_no_matching_region_id(self, mock_client):
        mock_client_instance = AsyncMock()
        mock_client.return_value = mock_client_instance
        mock_client_instance.get.return_value.json = MagicMock(
            return_value={
                "catalog": [
                    {
                        "type": "compute",
                        "endpoints": [
                            {
                                "interface": "public",
                                "region_id": "region2",
                                "url": "https://compute.example.com",
                            }
                        ],
                    }
                ]
            }
        )

        async with self.cloud as cloud:
            self.assertFalse(cloud.is_authenticated)
            self.assertEqual(cloud.apis, [])

    @patch("capi_janitor.openstack.openstack.Client")
    async def test_aenter_empty_endpoint_list(self, mock_client):
        mock_client_instance = AsyncMock()
        mock_client.return_value = mock_client_instance
        mock_client_instance.get.return_value.json = MagicMock(
            return_value={
                "catalog": [
                    {
                        "type": "compute",
                        "endpoints": []
                    }
                ]
            }
        )

        async with self.cloud as cloud:
            self.assertFalse(cloud.is_authenticated)
            self.assertEqual(cloud.apis, [])
