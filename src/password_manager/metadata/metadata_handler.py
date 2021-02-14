import json
import base64
import logging

from hashlib import sha3_512, md5
from cryptography.fernet import Fernet, InvalidToken

from .password_metadata import PasswordMetadata
from password_manager.hashing import prepare_hash
from password_manager.exceptions import AuthenticationFailed

logger = logging.getLogger(__name__)


class MetadataHandler:
    """
    Manages password metadata such as password lengths,
    charsets, updates etc.
    """

    def __init__(self,
                 password: str,
                 metadata_file: str):
        """
        :param password:        encryption password
        :param metadata_file:   path to the metadata file
        """
        self._metadata_file = metadata_file

        self.device_keys: set = None
        self.device_authentication_hash: str = None
        self._master_password: str = password
        self._password_metadata: dict = None

        encryption_key = self._prepare_key(password)
        self._fernet = Fernet(encryption_key)

        self._load_file()

    def add_device_key(self, device_key: int):
        """
        Adds the given key to the know device key set

        :param device_key:      current device key
        """
        self.device_keys.add(device_key)
        self._save()

    def set_device_authentication_hash(self, device_authentication_hash: str):
        """
        Adds the given authentication hash to metadata
        """
        self.device_authentication_hash = device_authentication_hash
        self._save()

    def remove_device_key(self, device_key: int):
        """
        Removes the given device key from the device key set

        :param device_key:      the device key to be removed
        """
        try:
            self.device_keys.remove(device_key)
            self._save()

        except KeyError:
            logger.warning(
                'Device key not found, not removing'
            )

    def get_metadata(self, checksum: str) -> PasswordMetadata:
        """
        :returns:       corresponding metadata
        :raises:        KeyError if no metadata found for the given checksum
        """
        if checksum not in self._password_metadata:
            raise KeyError(
                'Checksum not found'
            )
        return self._password_metadata[checksum]

    def add_metadata(self, metadata: PasswordMetadata):
        """
        Adds a new metadata entry

        :param metadata:    new metadata
        :raises:            ValueError if the given checksum
                            is already present
        """
        if metadata.checksum in self._password_metadata:
            raise ValueError(
                'Metadata already present'
            )

        self._password_metadata[metadata.checksum] = metadata
        self._save()

    def update_metadata(self, metadata: PasswordMetadata):
        """
        Updates metadata for the given checksum

        :param metadata:    password metadata
        :raises:            KeyError if the given checksum is not present
        """
        if metadata.checksum not in self._password_metadata:
            raise KeyError(
                'Metadata not found'
            )

        self._password_metadata[metadata.checksum] = metadata
        self._save()

    def delete_metadata(self, checksum: str):
        """
        Deletes corresponding metadata

        :param checksum:    checksum for the given password
        :raises:            KeyError if the given checksum is not present
        """
        self._password_metadata.pop(checksum)
        self._save()

    def _save(self):
        """
        Encrypts and saves metadata
        """
        data = bytes(
            json.dumps({
                'device_authentication_hash': self.device_authentication_hash,
                'device_keys': list(self.device_keys),
                'password_metadata': [
                    d.to_dict()
                    for d in self._password_metadata.values()
                ]
            }),
            'utf-8'
        )

        with open(self._metadata_file, 'wb') as f:
            f.write(
                self._fernet.encrypt(data)
            )

    def _load_file(self):
        """
        Loads metadata from the given encrypted file
        or starts from scratch if no file is found
        """
        try:
            with open(self._metadata_file, 'rb') as f:
                data = json.loads(
                    self._fernet.decrypt(
                        f.read()
                    )
                )

            self.device_keys = set(data['device_keys'])
            self.device_authentication_hash = data['device_authentication_hash']
            self._password_metadata = {
                d['checksum']: PasswordMetadata.from_dict(d)
                for d in data['password_metadata']
            }

        except FileNotFoundError:
            logger.info('Starting from scratch')

            self.device_keys = set()
            self._password_metadata = {}

        except InvalidToken:
            raise AuthenticationFailed(
                'Invalid password'
            )

    @staticmethod
    def _prepare_key(password: str) -> bytes:
        """
        Prepares fernet encryption key from the given password.

        :param password:    input password
        :return:            encryption key
        """
        sha512_hash = prepare_hash(
            password,
            n_iterations=100,
            digestmod=sha3_512
        )

        a = int(sha512_hash, 16) ** 1200

        tmp = prepare_hash(
            str(a),
            n_iterations=100,
            digestmod=md5
        )
        return base64.b64encode(bytes(tmp, 'UTF-8'))
