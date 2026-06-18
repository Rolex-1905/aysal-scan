from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("aysal-scan")
except PackageNotFoundError:
    # Package not installed (running from source without pip install -e .)
    __version__ = "0.0.0-dev"