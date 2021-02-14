import secrets
import logging
import pyperclip

from password_manager.core import PasswordMaker
from password_manager.metadata import (
    MetadataHandler,
    PasswordMetadata
)
from password_manager.exceptions import AuthenticationFailed

logger = logging.getLogger(__name__)


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
        Asks user for the desired input, generates
        the corresponding password and copies it to the clipboard

        :raises AuthenticationFailed:   on wrong password or unknown input
        """
        current_input = input('Current input: ')
        self._get_password(current_input)

    def _get_password(self,
                      current_input: str,
                      which='current',
                      output_method='clip'):
        """
        Generates the password for the given input
        and copies it to the clipboard.

        :param current_input:           users input
        :param which:                   which password to generate
                                        <current|old>
        :param output_method:           <clip|terminal>

        :raises AuthenticationFailed:   on wrong password or unknown input
        """
        checksum = self._password_maker.get_checksum(
            f'{self._master_password}-{self._device_token}-{current_input}'
        )

        try:
            metadata = self._metadata_handler.get_metadata(checksum)

        except KeyError:
            raise AuthenticationFailed(
                f'Unknown input: {current_input}'
            )

        if which.lower() == 'current':
            salt = metadata.salt
        elif which.lower() == 'old':
            salt = metadata.old_salt
        else:
            raise ValueError(
                f'Unknown option: {which}'
            )

        pswd = self._password_maker.get_password(
            f'{self._master_password}-{self._device_token}-'
            f'{salt}-{current_input}',
            character_options=metadata.charset,
            length=metadata.length
        )

        if output_method.lower() == 'clip':
            pyperclip.copy(pswd)
            logger.info(
                f'The password has been copied '
                f'to the clipboard'
            )
        elif output_method.lower() == 'terminal':
            print(f'Password: {pswd}')
        else:
            raise ValueError(
                f'Unknown output method: {output_method}'
            )

    def add_password(self):
        """
        Asks user for new password details and
        adds the corresponding password to the manager.
        """
        logger.info('Adding a new password to the password manager')

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

        :param new_input:       desired input
        :param charset:         desired character set <l|u|d|p>
        :param length:          desired password length
        """
        checksum = self._password_maker.get_checksum(
            f'{self._master_password}-{self._device_token}-{new_input}'
        )
        salt = secrets.token_hex(32)
        metadata = PasswordMetadata(
            checksum=checksum,
            charset=charset,
            length=length,
            salt=salt,
            old_salt=salt
        )
        self._metadata_handler.add_metadata(metadata)

    def delete_password(self):
        """
        Deletes the corresponding input.
        """
        current_input = input('Current input: ')
        logger.info(f'Will delete password for: {current_input}')

        confirm = input('Delete? [y/N]')

        if confirm.lower() == 'y':
            try:
                self._delete_password(current_input)
                logger.info(f'Deleted password for {current_input}')
            except KeyError:
                logger.warning(f'No password found for: {current_input}')
        else:
            logger.info('Not deleting')

    def _delete_password(self, current_input: str):
        """
        Performs the password removal.

        :param current_input:       input to remove
        """
        checksum = self._password_maker.get_checksum(
            f'{self._master_password}-{self._device_token}-{current_input}'
        )

        self._metadata_handler.delete_metadata(checksum)

    def update_password(self):
        """
        Asks user for the desired input and updates
        the corresponding password
        """
        current_input = input('Current input: ')
        logger.info(f'Will update password for: {current_input}')

        confirm = input('Update? [y/N]')

        if confirm.lower() == 'y':
            self._update_password(current_input)
            logger.info(f'Updated password for: {current_input}')
        else:
            logger.info('Not updating')

    def _update_password(self, current_input: str):
        """
        Performs the password update.

        :param current_input:       users input
        """
        checksum = self._password_maker.get_checksum(
            f'{self._master_password}-{self._device_token}-{current_input}'
        )

        try:
            metadata = self._metadata_handler.get_metadata(checksum)

        except KeyError:
            raise AuthenticationFailed(
                f'Unknown input: {current_input}'
            )

        metadata.old_salt = metadata.salt
        metadata.salt = secrets.token_hex(32)

        self._metadata_handler.update_metadata(metadata)

    def get_old_password(self):
        """
        Generates password for the given input as it was prior to an update.
        """
        current_input = input('Current input: ')
        logger.info(f'Will generate old password')
        self._get_password(current_input, which='old')

    def print_password(self):
        """
        Asks user for the desired input and generates
        the corresponding password and prints it to the terminal

        :raises AuthenticationFailed:   on wrong password or unknown input
        """
        current_input = input('Current input: ')

        confirm = input(
            'Do you want to print the password to terminal? [y/N]'
        )
        if confirm.lower() == 'y':
            self._get_password(current_input, output_method='terminal')
        else:
            logger.info('Not printing the password')
