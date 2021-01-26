import time
import pytest

from password_manager.core.password_maker import PasswordMaker


@pytest.fixture()
def password_maker() -> PasswordMaker:
    return PasswordMaker()


def test_get_password(password_maker):
    """
    Assert password making takes at least 100 ms
    """
    prior = time.time()

    pswd = password_maker.get_password(
        input_string='test',
        character_options='ludp',
        length=32
    )

    assert time.time() - prior > 0.1
    assert type(pswd) == str
    assert len(pswd) == 32


def test_get_checksum(password_maker):
    """
    Assert checksum making takes at least 200 ms
    """
    prior = time.time()

    checksum = password_maker.get_checksum(
        input_string='test',
        length=32
    )

    assert time.time() - prior > 0.2
    assert type(checksum) == str
    assert len(checksum) == 32
