#!/bin/python3
import os
import sys
import getpass
import logging

from pathlib import Path

from password_manager import (
    PasswordManager, MetadataHandler, DeviceAuthenticator
)
from password_manager.exceptions import AuthenticationFailed
from password_manager.tools.command_line import parse_args, OperationMode

MIKOS_PASSWORD_MANAGER_DIR = os.getenv(
    'MIKOS_PASSWORD_MANAGER_DIR',
    '../'
)
METADATA_FILENAME = 'metadata'

logger = logging.getLogger(__name__)
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=logging.INFO
)

args = parse_args()


def prepare_password_manager() -> PasswordManager:
    data_dir = Path(MIKOS_PASSWORD_MANAGER_DIR) / 'data'
    data_dir.mkdir(exist_ok=True)
    metadata_file = data_dir / METADATA_FILENAME

    if not Path(metadata_file).is_file():
        logger.info('Need to create the master password')
        master_password = getpass.getpass('Master password: ')
        confirm = getpass.getpass('Confirm master password: ')
        if not master_password == confirm:
            logger.error('Passwords don\'t match')
            sys.exit(0)
    else:
        master_password = getpass.getpass('Master password: ')

    try:
        metadata_handler = MetadataHandler(
            password=master_password,
            metadata_file=metadata_file
        )

        if metadata_handler.device_authentication_hash:
            device_authenticator = DeviceAuthenticator(
                metadata_handler.device_authentication_hash,
                device_keys=metadata_handler.device_keys
            )
        else:
            logger.info(
                'Need to create the device authentication password'
            )
            device_authentication_hash = \
                DeviceAuthenticator.make_authentication_hash()
            device_authenticator = DeviceAuthenticator(
                device_authentication_hash,
                device_keys=metadata_handler.device_keys
            )
            metadata_handler.set_device_authentication_hash(
                device_authentication_hash
            )
    except AuthenticationFailed as e:
        logger.error(e)
        sys.exit(0)

    try:
        device_token = device_authenticator.authenticate()
        logger.info('Device authenticated')
    except AuthenticationFailed:
        logger.info('Need to authenticate the device')
        device_key = device_authenticator.make_device_key()

        metadata_handler.add_device_key(device_key)
        device_token = device_authenticator.authenticate()

    return PasswordManager(
        master_password,
        device_token,
        metadata_handler
    )


def main(password_manager):
    try:
        if args.mode == OperationMode.GET:
            password_manager.get_password()
        elif args.mode == OperationMode.ADD:
            password_manager.add_password()
        elif args.mode == OperationMode.UPDATE:
            password_manager.update_password()
        elif args.mode == OperationMode.DELETE:
            password_manager.delete_password()
        elif args.mode == OperationMode.PRINT:
            password_manager.print_password()
        elif args.mode == OperationMode.GET_OLD:
            password_manager.get_old_password()
        else:
            raise NotImplementedError
    except AuthenticationFailed as err:
        logger.error(err)
        sys.exit(0)


if __name__ == '__main__':
    manager = prepare_password_manager()
    main(manager)
