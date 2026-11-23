"""Exception types used across LayerSecOps."""

from __future__ import annotations


class LayerSecOpsError(Exception):
    """Base class for expected, user-facing failures."""

    exit_code = 2


class ConfigError(LayerSecOpsError):
    """Invalid configuration or command-line combination."""

    exit_code = 3


class ToolNotFoundError(LayerSecOpsError):
    """A required external tool could not be located."""

    exit_code = 2


class ToolExecutionError(LayerSecOpsError):
    """An external tool ran but failed."""

    exit_code = 2


class ImageLoadError(LayerSecOpsError):
    """The image archive could not be read or saved."""

    exit_code = 2


class ReportError(LayerSecOpsError):
    """A report could not be written or read."""

    exit_code = 2
