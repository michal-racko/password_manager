import pytest

from password_manager.metadata import MetadataHandler, PasswordMetadata

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
        charset='ludp',
        length=32
    )


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
        salt=mock_metadata.checksum,
        charset='lud',
        length=22
    )

    metadata_handler.update_metadata(updated)

    test_metadata = metadata_handler.get_metadata(updated.checksum)
    assert updated == test_metadata


def test_save_load(mock_metadata,
                   metadata_handler):
    metadata_handler.add_metadata(mock_metadata)

    test_metadata = metadata_handler.get_metadata(mock_metadata.checksum)
    assert mock_metadata == test_metadata

    metadata_handler.save()
    metadata_handler.delete_metadata(mock_metadata.checksum)

    assert mock_metadata.checksum not in metadata_handler._password_metadata

    metadata_handler._load_file()
    test_metadata = metadata_handler.get_metadata(mock_metadata.checksum)

    assert mock_metadata == test_metadata
