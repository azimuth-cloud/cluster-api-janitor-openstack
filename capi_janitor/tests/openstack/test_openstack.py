import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from capi_janitor.openstack.openstack import AuthenticationError, Cloud


class TestCloudAsyncContext(unittest.IsolatedAsyncioTestCase):
    # Set up common variables for all tests
    async def asyncSetUp(self):
        # Auth is mocked to simulate authentication
        self.auth = MagicMock()
        # Transport is awaited so can be Async Mocked
        self.transport = AsyncMock()
        # Interface & Region can be fixed for the tests
        self.interface = "public"
        self.region = "region1"
        # Create a Cloud instance with the mocked auth and transport
        self.cloud = Cloud(self.auth, self.transport, self.interface, self.region)

    # Test the __aenter__ method for auth success and general functionality
    @patch("capi_janitor.openstack.openstack.Client")
    async def test_cloud_successful_authentication(self, mock_client):
        # Patched client to simulate a successful authentication
        mock_client_instance = AsyncMock()
        # Return mock for the client
        mock_client.return_value = mock_client_instance
        # Mock the get method to return a simple successful response
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
        # Mock the base_url for the client
        mock_client_instance._base_url = "https://compute.example.com"

        # Assert return values
        async with self.cloud as cloud:
            self.assertTrue(cloud.is_authenticated)
            self.assertIn("compute", cloud.apis)
            self.assertEqual(
                cloud.api_client("compute")._base_url, "https://compute.example.com"
            )
            mock_client_instance.get.assert_called_once_with("/v3/auth/catalog")

    # Test the __aenter__ method for auth failure
    @patch("capi_janitor.openstack.openstack.Client")
    async def test_cloud_authentication_failure(self, mock_client):
        mock_client_instance = AsyncMock()
        mock_client.return_value = mock_client_instance
        # Simulate an auth error with a named user
        mock_client_instance.get.side_effect = AuthenticationError("test_user")

        with self.assertRaises(AuthenticationError) as context:
            async with self.cloud:
                pass
        # Assert that the AuthenticationError is raised with the correct message
        self.assertEqual(
            str(context.exception), "failed to authenticate as user: test_user"
        )

    # Test the __aenter__ method for 404 error
    @patch("capi_janitor.openstack.openstack.Client")
    async def test_cloud_auth_404_error(self, mock_client):
        mock_client_instance = AsyncMock()
        mock_client.return_value = mock_client_instance
        # Simulate a 404 error
        mock_client_instance.get.side_effect = MagicMock(
            response=MagicMock(status_code=404)
        )

        # Assert auth failed and no endpoints are returned
        async with self.cloud as cloud:
            self.assertFalse(cloud.is_authenticated)
            self.assertEqual(cloud.apis, [])

    # Test the __aenter__ method for no matching interface
    @patch("capi_janitor.openstack.openstack.Client")
    async def test_cloud_no_matching_interface(self, mock_client):
        mock_client_instance = AsyncMock()
        mock_client.return_value = mock_client_instance
        # No matching interface in the response
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
    async def test_cloud_no_matching_region_id(self, mock_client):
        mock_client_instance = AsyncMock()
        mock_client.return_value = mock_client_instance
        # No matching region_id in the response
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
    async def test_cloud_filter_endpoints(self, mock_client):
        mock_client_instance = AsyncMock()
        mock_client.return_value = mock_client_instance
        # Return multiple endpoints, one matching, one not
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
                    },
                    {
                        "type": "network",
                        "endpoints": [
                            {
                                "interface": "internal",
                                "region_id": "region1",
                                "url": "https://network.example.com",
                            }
                        ],
                    },
                ]
            }
        )

        async with self.cloud as cloud:
            self.assertTrue(cloud.is_authenticated)
            self.assertIn("compute", cloud.apis)
            self.assertNotIn("network", cloud.apis)

    @patch("capi_janitor.openstack.openstack.Client")
    async def test_cloud_multiple_services(self, mock_client):
        mock_client_instance = AsyncMock()
        mock_client.return_value = mock_client_instance
        # Return multiple services, some matching, some not
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
                    },
                    {
                        "type": "storage",
                        "endpoints": [
                            {
                                "interface": "internal",
                                "region_id": "region1",
                                "url": "https://storage.example.com",
                            }
                        ],
                    },
                    {
                        "type": "network",
                        "endpoints": [
                            {
                                "interface": "public",
                                "region_id": "region1",
                                "url": "https://network.example.com",
                            }
                        ],
                    },
                ]
            }
        )

        async with self.cloud as cloud:
            self.assertTrue(cloud.is_authenticated)
            self.assertIn("compute", cloud.apis)
            self.assertNotIn("storage", cloud.apis)
            self.assertIn("network", cloud.apis)

    @patch("capi_janitor.openstack.openstack.Client")
    async def test_cloud_empty_endpoint_list(self, mock_client):
        mock_client_instance = AsyncMock()
        mock_client.return_value = mock_client_instance
        mock_client_instance.get.return_value.json = MagicMock(
            return_value={"catalog": [{"type": "compute", "endpoints": []}]}
        )

        async with self.cloud as cloud:
            self.assertFalse(cloud.is_authenticated)

    @patch("capi_janitor.openstack.openstack.Client")
    async def test_cloud_no_region_specified(self, mock_client):
        # Set up the cloud instance without a region
        self.cloud = Cloud(self.auth, self.transport, self.interface, region=None)
        mock_client_instance = AsyncMock()
        mock_client.return_value = mock_client_instance
        # Return endpoints with different region_ids
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
                    },
                    {
                        "type": "network",
                        "endpoints": [
                            {
                                "interface": "public",
                                "region_id": "region2",
                                "url": "https://network.example.com",
                            }
                        ],
                    },
                ]
            }
        )

        async with self.cloud as cloud:
            self.assertTrue(cloud.is_authenticated)
            self.assertIn("compute", cloud.apis)
            self.assertIn("network", cloud.apis)
