import random
import string

from hashlib import sha3_256, sha3_384, sha3_512

from password_manager.hashing import prepare_hash


class PasswordMaker:
    def __init__(self):
        self._characters = {
            'l': string.ascii_lowercase,
            'u': string.ascii_uppercase,
            'd': string.digits,
            'p': string.punctuation
        }

    def get_checksum(self,
                     input_string: str,
                     length=32) -> str:
        """
        Uses a combination of SHA3 algorithms to generate
        a checksum based on the given input string. A CPU heavy
        task (~0.1 CPU seconds) is used to prepare a character
        mapping. Result should be used to validate the input string.

        :param input_string:        base string for the password
        :param length:              desired checksum length
        """
        sha384_hash = prepare_hash(
            input_string,
            n_iterations=100,
            digestmod=sha3_384
        )
        sha256_hash = prepare_hash(
            input_string,
            n_iterations=100,
            digestmod=sha3_256
        )

        a = int(sha384_hash, 16) ** 1000
        b = int(sha256_hash, 16) ** 1500

        seed = str(a + b)
        characters = self._get_characters(options='ludp')
        character_mapping = self._get_character_mapping(
            seed,
            characters
        )

        if length > len(sha384_hash):
            pass  # TODO: warning log

        return ''.join([
            character_mapping[c] for c in sha384_hash[:length]
        ])

    def get_password(self,
                     input_string: str,
                     character_options: str,
                     length: int) -> str:
        """
        Uses a combination of SHA3 algorithms to generate
        a password based on the given input string. A CPU heavy
        task (~0.1 CPU seconds) is used to prepare a character
        mapping.

        :param input_string:        base string for the password
        :param character_options:   charsets to be used <l|u|d|p>
        :param length:              desired password length
        """
        sha512_hash = prepare_hash(
            input_string,
            n_iterations=100,
            digestmod=sha3_512
        )
        sha256_hash = prepare_hash(
            input_string,
            n_iterations=100,
            digestmod=sha3_256
        )

        a = int(sha512_hash, 16) ** 500
        b = int(sha256_hash, 16) ** 1500

        seed = str(a + b)
        characters = self._get_characters(character_options)
        character_mapping = self._get_character_mapping(
            seed,
            characters
        )

        if length > len(sha512_hash):
            pass  # TODO: warning log

        return ''.join([
            character_mapping[c] for c in sha512_hash[:length]
        ])

    @staticmethod
    def _get_character_mapping(seed: int,
                               characters: str) -> dict:
        """
        Prepares mapping from hexdigit charset
        to the given charset

        :param seed:            A random seed to be used
        :param characters:      Characters to choose from
        """
        random.seed(seed)
        return {
            h: c for h, c in zip(
                string.hexdigits,
                random.choices(
                    characters,
                    k=16
                )
            )
        }

    def _get_characters(self, options: str) -> str:
        """
        Prepares characters based on the given options

        :param options:     character options
        :return:            string with chosen characters
        """
        res = ''

        for o in list(options):
            res += self._characters.get(o, '')

        if len(res) == 0:
            raise ValueError('No characters to chose from')

        return res
