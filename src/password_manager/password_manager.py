from .hashing import prepare_hash
from .device_authenticator import DeviceAuthenticator


class PasswordManager:
    def __init__(self,
                 master_password: str,
                 device_authenticator: DeviceAuthenticator):
        self._device_authenticator = device_authenticator
        self._master_password = master_password

        self._checksums = []

    def add_checksum(self, checksum: str):
        self._checksums.append(checksum)

    def get_password(self) -> str:
        current_input = input('Current input:')

        return self._get_password(current_input)

    def _get_password(self, current_input: str) -> str:
        device_token = self._device_authenticator.authenticate()

        prepare_hash(
            f'{self._master_password}-{device_token}-{current_input}',
            n_iterations=50
        )

    def make_checksum(self, current_input: str) -> str:
        pass
