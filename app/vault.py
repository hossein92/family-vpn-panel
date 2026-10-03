"""At-rest encryption for generated .ovpn files during their download window."""
import os

from cryptography.fernet import Fernet, InvalidToken

from . import config

_f = None


def _fernet():
    global _f
    if _f is None:
        path = config.SECRET_KEY_FILE
        if not path.exists():
            if not config.FAKE:
                raise RuntimeError(f"{path} missing — run the installer")
            path.write_bytes(Fernet.generate_key())
            os.chmod(path, 0o600)
        _f = Fernet(path.read_bytes().strip())
    return _f


def seal(text):
    return _fernet().encrypt(text.encode())


def unseal(blob):
    try:
        return _fernet().decrypt(blob).decode()
    except InvalidToken as e:
        raise RuntimeError("profile cannot be decrypted (key changed?)") from e
