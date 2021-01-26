import json
import base64
import logging

from hashlib import sha3_512, md5
from cryptography.fernet import Fernet

from .password_metadata import PasswordMetadata
from password_manager.hashing import prepare_hash


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

        encryption_key = self._prepare_key(password)
        self._fernet = Fernet(encryption_key)

        self.device_keys: list = None
        self._password_metadata: dict = None

        self._load_file()

    def get_metadata(self, checksum: str) -> PasswordMetadata:
        """
        :returns:       corresponding metadata
        :raises:        KeyError if no metadata found for the given checksum
        """
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

    def delete_metadata(self, checksum: str):
        """
        Deletes corresponding metadata
        """
        try:
            self._password_metadata.pop(checksum)

        except KeyError:
            logging.warning('Metadata not found, not deleting')

    def save(self):
        """
        Encrypts and saves the metadata
        """
        data = bytes(
            json.dumps({
                'device_keys': self.device_keys,
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

            self.device_keys = data['device_keys']
            self._password_metadata = {
                d['checksum']: PasswordMetadata.from_dict(d)
                for d in data['password_metadata']
            }

        except FileNotFoundError:
            logging.warning('No metadata found. Starting from scratch')

            self.device_keys = []
            self._password_metadata = {}

    @staticmethod
    def _prepare_key(password: str) -> bytes:
        """
        Prepares fernet encryption key from the given password.

        :param password:    input password
        :return:            encryption key
        """
        tmp = prepare_hash(
            password,
            digestmod=sha3_512
        )
        tmp = prepare_hash(
            tmp,
            digestmod=md5
        )
        return base64.b64encode(bytes(tmp, 'UTF-8'))
