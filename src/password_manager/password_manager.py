import logging
import pyperclip

from password_manager.core import (
    DeviceAuthenticator,
    PasswordMaker
)
from password_manager.metadata import (
    MetadataHandler,
    PasswordMetadata
)
from password_manager.exceptions import AuthenticationFailed


class PasswordManager:
    """
    Provides an interface for the password keeper.
    """

    def __init__(self,
                 master_password: str,
                 metadata_file: str):
        self._metadata_handler = MetadataHandler(
            password=master_password,
            metadata_file=metadata_file
        )

        if self._metadata_handler.device_authentication_hash:
            device_authenticator = DeviceAuthenticator(
                self._metadata_handler.device_authentication_hash,
                device_keys=self._metadata_handler.device_keys
            )

        else:
            device_authentication_hash = \
                DeviceAuthenticator.make_authentication_hash()
            device_authenticator = DeviceAuthenticator(
                device_authentication_hash,
                device_keys=self._metadata_handler.device_keys
            )

        try:
            self._device_token = device_authenticator.authenticate()

        except AuthenticationFailed:
            logging.info('Need to authenticate the device')
            device_key = device_authenticator.make_device_key()

            self._metadata_handler.add_device_key(device_key)
            self._metadata_handler.save()

            self._device_token = device_authenticator.authenticate()

        self._master_password = master_password

        self._password_maker = PasswordMaker()

    def get_password(self):
        """
        Generates the password for the given input
        and copies it to the clipboard.

        :raises AuthenticationFailed:   on wrong password or unknown input
        """
        current_input = input('Current input: ')

        checksum = self._password_maker.get_checksum(
            f'{self._password_maker}-{current_input}'
        )

        try:
            metadata = self._metadata_handler.get_metadata(checksum)

        except KeyError:
            raise AuthenticationFailed(
                'Unknown input'
            )

        pswd = self._password_maker.get_password(
            f'{self._password_maker}-{metadata.salt}-{current_input}',
            character_options=metadata.charset,
            length=metadata.length
        )

        pyperclip.copy(pswd)
        logging.info(
            f'Password for: {current_input} has been copied '
            f'to the clipboard'
        )

    def add_password(self):
        """
        Adds a new input to the manager.
        """
        pass

    def update_password(self):
        """
        Updates password for the given input.
        """
        pass

    def get_previous_password(self):
        """
        Generates password for the given input as it was prior to update.
        """
        pass
