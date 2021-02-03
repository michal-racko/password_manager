import getpass
import logging

from password_manager import (
    PasswordManager, MetadataHandler, DeviceAuthenticator
)
from password_manager.exceptions import AuthenticationFailed

METADATA_FILE = ''  # TODO: get from env + default

if __name__ == '__main__':
    master_password = getpass.getpass('Master password: ')

    metadata_handler = MetadataHandler(
        password=master_password,
        metadata_file=METADATA_FILE
    )

    if metadata_handler.device_authentication_hash:
        device_authenticator = DeviceAuthenticator(
            metadata_handler.device_authentication_hash,
            device_keys=metadata_handler.device_keys
        )

    else:
        device_authentication_hash = \
            DeviceAuthenticator.make_authentication_hash()
        device_authenticator = DeviceAuthenticator(
            device_authentication_hash,
            device_keys=metadata_handler.device_keys
        )

    try:
        device_token = device_authenticator.authenticate()

    except AuthenticationFailed:
        logging.info('Need to authenticate the device')
        device_key = device_authenticator.make_device_key()

        metadata_handler.add_device_key(device_key)
        metadata_handler.save()

        device_token = device_authenticator.authenticate()

    password_manager = PasswordManager(
        master_password,
        device_token,
        metadata_handler
    )
