class PasetoError(Exception):
    pass


class InvalidKeyError(PasetoError):
    pass


class BadSignatureError(PasetoError):
    pass


class ValueError(ValueError, PasetoError):
    pass


class PasetoWarning(RuntimeWarning):
    pass


class SecurityWarning(PasetoWarning):
    pass
