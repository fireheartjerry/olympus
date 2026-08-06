"""Fire public package facade.

The implementation remains in :mod:`olympus` for the first compatibility
release so deployed imports, migrations, and serialized identifiers do not
change underneath a live authority boundary.
"""

from olympus import __version__

__all__ = ["__version__"]
