from __future__ import annotations


class V2rmError(Exception):
    """Base class for all errors v2rm expects and reports as a clean CLI message."""


class ProfileNotFoundError(V2rmError):
    pass


class SubscriptionNotFoundError(V2rmError):
    pass


class AmbiguousReferenceError(V2rmError):
    pass


class ParseError(V2rmError):
    """A share-link or subscription payload could not be parsed."""


class FetchError(V2rmError):
    """A subscription URL could not be fetched."""


class EngineNotInstalledError(V2rmError):
    pass


class UnsupportedProtocolError(V2rmError):
    """Raised when a profile's protocol isn't supported by the selected engine."""


class NotConnectedError(V2rmError):
    pass


class AlreadyConnectedError(V2rmError):
    pass


class ConnectFailedError(V2rmError):
    """The engine process failed to start or die immediately after launch."""


class DownloadError(V2rmError):
    pass


class ChecksumError(DownloadError):
    pass


class StoreLockTimeoutError(V2rmError):
    pass


class RouteValidationError(V2rmError):
    pass
