from dataclasses import dataclass


@dataclass
class PasswordMetadata:
    """
    A data class for the given password

    checksum    - checksum for the given password
    salt        - a string which will be added to the
                  input before hashing
    old_salt    - an old version of salt (after a password update)
    charset     - character settings <l|u|d|p>
                    l - lowercase letters
                    u - uppercase letters
                    d - digits
                    p - punctuation
    length      - password length
    """

    checksum: str
    salt: str
    old_salt: str
    charset: str
    length: int

    def to_dict(self) -> dict:
        return {
            'checksum': self.checksum,
            'salt': self.salt,
            'old_salt': self.old_salt,
            'charset': self.charset,
            'length': self.length
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            checksum=data['checksum'],
            salt=data['salt'],
            old_salt=data['old_salt'],
            charset=data['charset'],
            length=data['length']
        )
