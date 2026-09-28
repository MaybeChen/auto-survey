"""Deterministic filtering for non-API static resource requests."""
from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import PurePosixPath

from src.config import AnalysisConfig
from src.models import Transaction


def should_ignore_transaction(
    transaction: Transaction, config: AnalysisConfig
) -> bool:
    """Return true when a request path matches a configured static-resource rule."""
    path = transaction.request.path.casefold()
    patterns = [pattern.casefold() for pattern in config.ignore_paths]
    if any(fnmatchcase(path, pattern) for pattern in patterns):
        return True
    suffix = PurePosixPath(path).suffix
    extensions = {
        extension.casefold()
        if extension.startswith(".")
        else f".{extension.casefold()}"
        for extension in config.ignore_extensions
    }
    return bool(suffix and suffix in extensions)
