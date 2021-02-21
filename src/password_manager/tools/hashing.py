import hmac

from hashlib import sha3_512


def prepare_hash(entry: str,
                 n_iterations=10,
                 digestmod=sha3_512) -> str:
    """
    :param entry:           String entry to be hashed
    :param n_iterations:    How many times to apply hmac
    :param digestmod:       hmac digestmod
    :return:                Calculated hash
    """
    res = entry

    for _ in range(n_iterations):
        res = hmac.new(
            bytes(res, 'utf-8'),
            digestmod=digestmod
        ).hexdigest()

    return res
