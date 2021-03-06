import uuid
import getpass

from hashlib import sha3_256

from password_manager.tools.hashing import prepare_hash
from password_manager.exceptions import AuthenticationFailed


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

    def __init__(self,
                 authentication_hash: str,
                 device_keys: set = None):
        """
        :param authentication_hash:         hash to do the authentication against
        :param device_keys:                 a set of known device keys
        """
        self._authentication_hash = authentication_hash

        if device_keys is None:
            self._device_keys = set()

        else:
            self._device_keys = device_keys

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

        return prepare_hash(str(k), digestmod=sha3_256)

    def make_device_key(self) -> int:
        """
        Prepares a new device key based on the device authentication password
        and adds it to the device key set
        """
        pswd = getpass.getpass('Device authentication password: ')
        return self._make_device_key(pswd)

    def _make_device_key(self, pswd: str) -> int:
        """
        Generates corresponding device key.

        :param pswd:        device authentication password
        :return:            device key
        """
        dev_add_hash = prepare_hash(pswd)
        k = int(dev_add_hash, 16)
        k_hash = prepare_hash(str(k))

        if k_hash != self._authentication_hash:
            raise AuthenticationFailed(
                'Wrong password'
            )

        device_id = self._get_device_id()
        device_key = k - device_id

        self._device_keys.add(device_key)

        return device_key

    @classmethod
    def make_authentication_hash(cls) -> str:
        """
        Prepares a new authentication hash
        """
        pswd = getpass.getpass('Device authentication password: ')
        if pswd != getpass.getpass('Confirm passwords: '):
            raise AuthenticationFailed(
                'passwords do not match'
            )

        return cls._make_authentication_hash(pswd)

    @classmethod
    def _make_authentication_hash(cls, pswd: str) -> str:
        """
        Generates a new authentication hash

        :param pswd:        password for the hash
        :return:            authentication hash
        """
        dev_add_hash = prepare_hash(pswd)
        k = int(dev_add_hash, 16)
        return prepare_hash(str(k))

    @staticmethod
    def _get_device_id(n_iterations=10) -> int:
        """
        Prepares a unique id based on the device uuid

        :param n_iterations:        n iterations for the hash
        :return:                    device id
        """
        res = str(uuid.getnode())
        res = prepare_hash(res, n_iterations=n_iterations, digestmod=sha3_256)
        return int(res, 16)
