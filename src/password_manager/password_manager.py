import secrets
import logging
import pyperclip

from password_manager.core import PasswordMaker
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
                 device_token: str,
                 metadata_handler: MetadataHandler):
        self._metadata_handler = metadata_handler

        self._device_token = device_token
        self._master_password = master_password

        self._password_maker = PasswordMaker()

    def get_password(self):
        """
        Asks user for the desired input and generates
        the corresponding password

        :raises AuthenticationFailed:   on wrong password or unknown input
        """
        current_input = input('Current input: ')
        self._get_password(current_input)

    def _get_password(self, current_input: str):
        """
        Generates the password for the given input
        and copies it to the clipboard.

        :param current_input:           users input

        :raises AuthenticationFailed:   on wrong password or unknown input
        """
        checksum = self._password_maker.get_checksum(
            f'{self._master_password}-{self._device_token}-{current_input}'
        )

        try:
            metadata = self._metadata_handler.get_metadata(checksum)

        except KeyError:
            raise AuthenticationFailed(
                'Unknown input'
            )

        pswd = self._password_maker.get_password(
            f'{self._master_password}-{self._device_token}-'
            f'{metadata.salt}-{current_input}',
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
        Asks user for new password details and
        adds the corresponding password to the manager.
        """
        logging.info('Adding a new password to the password manager')

        new_input = input('New input: ')
        charset = input('Character set <l|u|d|p>: ')
        password_length = int(input('Password length: '))

        self._add_password(
            new_input=new_input,
            charset=charset,
            length=password_length
        )

    def _add_password(self,
                      new_input: str,
                      charset: str,
                      length: int):
        """
        Adds a new input to the manager.
        """
        checksum = self._password_maker.get_checksum(
            f'{self._master_password}-{self._device_token}-{new_input}'
        )
        metadata = PasswordMetadata(
            checksum=checksum,
            charset=charset,
            length=length,
            salt=secrets.token_hex(32)
        )
        self._metadata_handler.add_metadata(metadata)
        self._metadata_handler.save()

    def remove_password(self):
        """
        Removes the corresponding input.
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
