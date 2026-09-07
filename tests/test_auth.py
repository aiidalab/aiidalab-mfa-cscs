import unittest
from unittest.mock import MagicMock, call, patch

import requests

import start


class OidcDiscoveryTests(unittest.TestCase):
    @patch("start.time.sleep")
    @patch("start.requests.get")
    def test_retries_transient_connection_failure(self, get, sleep):
        response = MagicMock()
        response.json.return_value = {
            "device_authorization_endpoint": "https://example.com/device",
            "token_endpoint": "https://example.com/token",
        }
        get.side_effect = [requests.ConnectTimeout(), response]

        endpoints = start.discover_oidc()

        self.assertEqual(
            endpoints, ("https://example.com/device", "https://example.com/token")
        )
        self.assertEqual(get.call_count, 2)
        sleep.assert_called_once_with(1)

    @patch("start.time.sleep")
    @patch("start.requests.get", side_effect=requests.ConnectTimeout())
    def test_stops_after_bounded_retries(self, get, sleep):
        with self.assertRaises(requests.ConnectTimeout):
            start.discover_oidc()

        self.assertEqual(get.call_count, 3)
        self.assertEqual(sleep.call_args_list, [call(1), call(2)])


class TokenPollingTests(unittest.TestCase):
    @patch("start.time.sleep")
    @patch("start.requests.Session")
    def test_waits_before_first_poll(self, session_class, sleep):
        session = session_class.return_value.__enter__.return_value
        response = MagicMock(status_code=200)
        response.json.return_value = {"access_token": "token"}
        session.post.return_value = response

        token = start.poll_for_token(
            "https://example.com/token", "device-code", 5, float("inf")
        )

        self.assertEqual(token, "token")
        sleep.assert_called_once_with(5)
        session.post.assert_called_once()

    @patch("start.time.sleep")
    @patch("start.requests.Session")
    def test_backs_off_after_connection_failure(self, session_class, sleep):
        session = session_class.return_value.__enter__.return_value
        response = MagicMock(status_code=200)
        response.json.return_value = {"access_token": "token"}
        session.post.side_effect = [requests.ConnectTimeout(), response]

        token = start.poll_for_token(
            "https://example.com/token", "device-code", 5, float("inf")
        )

        self.assertEqual(token, "token")
        self.assertEqual(sleep.call_args_list, [call(5), call(10)])
        self.assertEqual(session.post.call_count, 2)


if __name__ == "__main__":
    unittest.main()
