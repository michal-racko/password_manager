import enum
import argparse


class OperationMode(enum.IntEnum):
    GET = 1
    ADD = 2
    UPDATE = 3
    DELETE = 4
    PRINT = 5
    GET_OLD = 6

    def __str__(self):
        return self.name.lower()

    def __repr__(self):
        return str(self)

    @staticmethod
    def argparse(s):
        try:
            return OperationMode[s.upper()]

        except KeyError:
            return s


def parse_args() -> argparse.Namespace:
    """
    Parses command line arguments

    :returns:       parsed command line arguments
    """
    parser = argparse.ArgumentParser(
        prog='main.py'
    )

    parser.add_argument(
        '-m',
        '--mode',
        help='Operation mode',
        type=OperationMode.argparse,
        choices=list(OperationMode),
        default=OperationMode.GET
    )

    return parser.parse_args()
