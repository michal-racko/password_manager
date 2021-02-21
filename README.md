# Password manager

A package for secure password generation. Uses a combination of sha3 algorithms and CPU-heavy tasks. All
configurations/metadata are stored in an encrypted file protected by a 32-character-long token also generated from the
master password (compromising this file would not be enough to compromise the actual passwords). Each password attempt
takes at least 100ms.

Uses a mechanism authenticating devices based on their device_ids. Each new device must be first authorized
using a device authentication password.

## Usage

`main.py [-h] [-m {get,add,update,delete,print,get_old}]`

The `-m` option selects the desired operational mode.

### Modes

- `get` - generates the desired password based on the given input, the password is then copied to the clipboard
- `add` - adds a new password to the manager; will ask for options:
    - New input - a key for the new password
    - Character set - desired character sets:
        - `l` - lower-case letters
        - `u` - upper-case letters
        - `d` - digits
        - `p` - punctuation
    - Password length - desired password length
- `update` - updates the desired password (length and character set remains the same)
- `delete` - deletes the corresponding password
- `print` - prints the desired password into terminal
- `get_old` - generates the corresponding password as it was before the last update

## Setup

Add `main.py` to the path.

Create a directory where the metada file will be stored.

`export MIKOS_PASSWORD_MANAGER_DIR=<dir>` - set the directory path where the metadata file will be stored (will be
created if not present)

- create a master password (you will be asked for it when first time calling `main.py`); this should be a fair password,
  will be asked for each time
- create a device authentication password (you will be asked for it when first time calling `main.py`); this should be a
  very strong password kept somewhere safe (will only be used once when running on a new device)
- authenticate the current device (type in the device authentication password)