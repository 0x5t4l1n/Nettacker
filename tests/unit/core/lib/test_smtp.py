import smtplib
from unittest.mock import patch

import pytest

from nettacker.core.lib.smtp import SmtpLibrary
from tests.unit.common import TestCase

SMTP_SESSION_PORT = 25


class MockSmtpConnectionObject:
    def __init__(self, *args, **kwargs):
        pass

    def login(self, user, password):
        return None

    def close(self):
        return None


class TestSmtpMethod(TestCase):
    @patch("nettacker.core.lib.smtp.SmtpLibrary.client")
    def test_brute_force_password(self, mock_smtp_client):
        library = SmtpLibrary()
        host = "mail.example.com"
        port = SMTP_SESSION_PORT
        username = "admin"
        password = "Password@123"
        timeout = 5

        mock_smtp_client.return_value = MockSmtpConnectionObject()

        self.assertEqual(
            library.brute_force(
                host=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
            ),
            {
                "host": host,
                "port": port,
                "username": username,
                "password": password,
            },
        )

        mock_smtp_client.assert_called_once_with(host, port, timeout=timeout)


@pytest.mark.parametrize(
    "error",
    [
        smtplib.SMTPAuthenticationError(535, b"Authentication failed"),
        smtplib.SMTPServerDisconnected("Connection unexpectedly closed"),
        TimeoutError("Login timed out"),
    ],
)
@patch("nettacker.core.lib.smtp.SmtpLibrary.client")
def test_brute_force_closes_connection_after_login_failure(mock_smtp_client, error):
    connection = mock_smtp_client.return_value
    connection.login.side_effect = error

    with pytest.raises(type(error)) as raised:
        SmtpLibrary().brute_force("mail.example.com", 25, "admin", "wrong", 5)

    assert raised.value is error
    connection.close.assert_called_once_with()


@patch("nettacker.core.lib.smtp.SmtpLibrary.client")
def test_brute_force_closes_connection_after_success(mock_smtp_client):
    connection = mock_smtp_client.return_value

    result = SmtpLibrary().brute_force("mail.example.com", 25, "admin", "password", 5)

    assert result == {
        "host": "mail.example.com",
        "port": 25,
        "username": "admin",
        "password": "password",
    }
    connection.login.assert_called_once_with("admin", "password")
    connection.close.assert_called_once_with()
