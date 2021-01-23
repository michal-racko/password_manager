import uuid
import getpass

from hashlib import sha256

from .hashing import prepare_hash
from .exceptions import AuthenticationFailed, PasswordError


class DeviceAuthenticator:
    """
    Can be used to authenticate the given device based on its hardware id.

    Device keys may be stored in plain text.
    The authentication hash may be stored in plain text.

    To authenticate:
        authenticator = DeviceAuthenticator(<authentication_hash: str>)
        authenticator.add_device_key(<device_key: int>)
        token = authenticator.authenticate()

    To prepare a new device key (will ask for password):
        authenticator = DeviceAuthenticator(<authentication_hash: str>)
        device_key = authenticator.make_device_key()

    To prepare a new authentication hash (need to setup a password):
        authentication_hash = DeviceAuthenticator.make_authentication_hash()
    """

    def __init__(self, authentication_hash: str):
        self._authentication_hash = authentication_hash
        self._device_keys = []

    def add_device_key(self, device_key: int):
        self._device_keys.append(device_key)

    def authenticate(self) -> str:
        """
        :returns:   Authentication token if the device is authenticated
        :raises:    AuthenticationFailed if the device is unknown
        """
        device_id = self._get_device_id()

        for device_key in self._device_keys:
            k = device_key + device_id
            if prepare_hash(str(k)) == self._authentication_hash:
                break

        else:
            raise AuthenticationFailed(
                'Unknown device'
            )

        return prepare_hash(str(k), digestmod=sha256)

    def make_device_key(self) -> int:
        """
        Prepares a new device key based on the device addition password
        """
        pswd = getpass.getpass('Device addition password: ')
        return self._make_device_key(pswd)

    def _make_device_key(self, pswd: str) -> int:
        dev_add_hash = prepare_hash(pswd)
        k = int(dev_add_hash, 16)
        k_hash = prepare_hash(str(k))

        if k_hash != self._authentication_hash:
            raise AuthenticationFailed(
                'Wrong password'
            )

        device_id = self._get_device_id()
        return k - device_id

    @classmethod
    def make_authentication_hash(cls) -> str:
        """
        Prepares a new authentication hash
        """
        pswd = getpass.getpass('Device addition password: ')
        if pswd != getpass.getpass('Confirm passwords: '):
            raise PasswordError(
                'passwords do not match'
            )

        return cls._make_authentication_hash(pswd)

    @classmethod
    def _make_authentication_hash(cls, pswd: str) -> str:
        dev_add_hash = prepare_hash(pswd)
        k = int(dev_add_hash, 16)
        return prepare_hash(str(k))

    @staticmethod
    def _get_device_id(n_iterations=10) -> int:
        res = str(uuid.getnode())
        res = prepare_hash(res, n_iterations=n_iterations, digestmod=sha256)
        return int(res, 16)
