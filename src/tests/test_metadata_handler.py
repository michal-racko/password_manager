import time
import pytest

from password_manager.metadata import MetadataHandler, PasswordMetadata
from password_manager.exceptions import AuthenticationFailed

PASSWORD = 'abc'


@pytest.fixture(scope='function')
def metadata_handler(tmp_path_factory) -> MetadataHandler:
    p = tmp_path_factory.mktemp('test_metadata') / 'pswd.data'
    return MetadataHandler(
        PASSWORD,
        metadata_file=p
    )


@pytest.fixture()
def mock_metadata() -> PasswordMetadata:
    return PasswordMetadata(
        checksum='abc',
        salt='def',
        old_salt='def',
        charset='ludp',
        length=32
    )


def test_prepare_key(metadata_handler):
    """
    Asserts the key preparation takes at least 0.2 seconds
    """
    prior = time.time()
    metadata_handler._prepare_key('abc')

    assert time.time() - prior > 0.2


def test_attributes(metadata_handler):
    assert hasattr(metadata_handler, 'device_keys')
    assert hasattr(metadata_handler, 'device_authentication_hash')


def test_add_device_key(metadata_handler):
    metadata_handler.add_device_key(1)

    assert 1 in metadata_handler.device_keys


def test_remove_device_key(metadata_handler):
    metadata_handler.add_device_key(1)
    metadata_handler.remove_device_key(1)

    assert 1 not in metadata_handler.device_keys


def test_add_metadata(mock_metadata,
                      metadata_handler):
    metadata_handler.add_metadata(mock_metadata)
    assert mock_metadata.checksum in metadata_handler._password_metadata

    test_metadata = metadata_handler.get_metadata(mock_metadata.checksum)
    assert mock_metadata == test_metadata


def test_update_metadata(mock_metadata,
                         metadata_handler):
    metadata_handler.add_metadata(mock_metadata)

    updated = PasswordMetadata(
        checksum=mock_metadata.checksum,
        salt='ghi',
        old_salt=mock_metadata.salt,
        charset='lud',
        length=22
    )

    metadata_handler.update_metadata(updated)

    test_metadata = metadata_handler.get_metadata(updated.checksum)
    assert updated == test_metadata


def test_delete_metadata(mock_metadata,
                         metadata_handler):
    metadata_handler.add_metadata(mock_metadata)
    assert mock_metadata.checksum in metadata_handler._password_metadata

    metadata_handler.delete_metadata(mock_metadata.checksum)

    with pytest.raises(KeyError):
        metadata_handler.get_metadata(mock_metadata.checksum)


def test_save_load(mock_metadata,
                   metadata_handler):
    metadata_handler.add_metadata(mock_metadata)
    metadata_handler.add_device_key(1)

    test_metadata = metadata_handler.get_metadata(mock_metadata.checksum)
    assert mock_metadata == test_metadata

    metadata_handler.save()
    metadata_handler.delete_metadata(mock_metadata.checksum)

    assert mock_metadata.checksum not in metadata_handler._password_metadata

    metadata_handler._load_file()
    test_metadata = metadata_handler.get_metadata(mock_metadata.checksum)

    assert mock_metadata == test_metadata
    assert 1 in metadata_handler.device_keys


def test_wrong_password(metadata_handler):
    metadata_handler.save()

    with pytest.raises(AuthenticationFailed):
        MetadataHandler(
            'wrong-pswd',
            metadata_file=metadata_handler._metadata_file
        )
