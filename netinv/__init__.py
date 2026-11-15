"""NetInventory: network and domain inventory."""
try:  # written by installer/build.ps1 (and the CI build) at build time
    from ._version import __version__
except ImportError:  # running from a source checkout
    __version__ = "0.0.0-dev"
