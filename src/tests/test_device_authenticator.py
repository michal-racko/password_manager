import pytest

from password_manager.exceptions import AuthenticationFailed
from password_manager.core.device_authenticator import DeviceAuthenticator

DEV_ADD_PSWD = 'abc'


@pytest.fixture()
def authentication_hash() -> str:
    return DeviceAuthenticator._make_authentication_hash(DEV_ADD_PSWD)


@pytest.fixture()
def device_authenticator(authentication_hash) -> DeviceAuthenticator:
    return DeviceAuthenticator(authentication_hash)


def test_authentication(device_authenticator):
    """
    Test adding a device key and using it for authentication
    """
    device_key = device_authenticator._make_device_key(DEV_ADD_PSWD)
    device_authenticator.add_device_key(device_key)
    token = device_authenticator.authenticate()

    assert type(token) == str


def test_wrong_password(device_authenticator):
    """
    Test a device key cannot be added without the correct password
    """
    with pytest.raises(AuthenticationFailed):
        device_authenticator._make_device_key('def')


def test_unauthorized(device_authenticator):
    """
    Test an unauthorized token request
    """
    with pytest.raises(AuthenticationFailed):
        device_authenticator.authenticate()
