"""
Integration tests for the PasswordManager class
"""

import pytest
import pyperclip

from password_manager.core import PasswordMaker
from password_manager.metadata import MetadataHandler, PasswordMetadata
from password_manager.password_manager import PasswordManager

MASTER_PASSWORD = 'abc'
DEVICE_TOKEN = 'def'
CURRENT_INPUT = 'test'

PASSWORD_LENGTH = 15


@pytest.fixture(scope='function')
def metadata_handler(tmp_path_factory) -> MetadataHandler:
    p = tmp_path_factory.mktemp('test_password_manager') / 'pswd.data'

    password_maker = PasswordMaker()
    handler = MetadataHandler(
        MASTER_PASSWORD,
        p
    )
    checksum = password_maker.get_checksum(
        f'{MASTER_PASSWORD}-{DEVICE_TOKEN}-{CURRENT_INPUT}'
    )
    metadata = PasswordMetadata(
        checksum=checksum,
        charset='ludp',
        length=PASSWORD_LENGTH,
        salt='ghi'
    )
    handler.add_metadata(metadata)

    return handler


def test_get_password(metadata_handler):
    password_manager = PasswordManager(
        master_password=MASTER_PASSWORD,
        device_token=DEVICE_TOKEN,
        metadata_handler=metadata_handler
    )

    password_manager._get_password(CURRENT_INPUT)
    res = pyperclip.paste()

    assert len(res) == PASSWORD_LENGTH
    assert type(res) == str


def test_add_password(metadata_handler):
    password_manager = PasswordManager(
        master_password=MASTER_PASSWORD,
        device_token=DEVICE_TOKEN,
        metadata_handler=metadata_handler
    )

    new_input = 'test-1'
    length = 20

    password_manager._add_password(
        new_input=new_input,
        charset='ludp',
        length=length
    )

    # test generating the new password
    password_manager._get_password(new_input)
    res = pyperclip.paste()

    assert len(res) == length
    assert type(res) == str
