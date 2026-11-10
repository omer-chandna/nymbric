"""Application errors. Permissions and provider failures are explicit."""


class NymbricError(Exception):
    """Base error for expected operational failures."""


class PermissionDenied(NymbricError):
    def __init__(self, message: str, *, tool: str | None = None, capability: str | None = None):
        super().__init__(message)
        self.tool = tool
        self.capability = capability


class DelegationDenied(NymbricError):
    pass


class ProviderUnavailable(NymbricError):
    """The selected inference provider cannot be used. No fallback is implied."""


class StructuredOutputError(NymbricError):
    pass


class BudgetExceeded(NymbricError):
    pass


class Cancelled(NymbricError):
    pass


class ConcurrentRunError(NymbricError):
    pass


class CheckpointError(NymbricError):
    pass


class ConfigError(NymbricError):
    pass
