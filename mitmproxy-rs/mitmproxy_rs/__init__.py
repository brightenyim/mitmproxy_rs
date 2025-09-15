import sys
import types
import platform
import shutil
import logging
from pathlib import Path

from .mitmproxy_rs import *

__doc__ = mitmproxy_rs.__doc__
if hasattr(mitmproxy_rs, "__all__"):
    __all__ = mitmproxy_rs.__all__

logger = logging.getLogger(__name__)


def _ensure_windivert_dependencies():
    """
    Ensure WinDivert DLL dependencies are available for Windows functionality.
    This function copies WinDivert DLL from the package to the current directory if needed.
    """
    if platform.system() != "Windows":
        return True
        
    try:
        # Get the current package directory
        package_dir = Path(__file__).parent
        
        # Check if WinDivert.dll already exists in the package directory
        windivert_dll = package_dir / "WinDivert.dll"
        if windivert_dll.exists():
            logger.debug("WinDivert.dll already exists in package directory")
            return True
        
        # Try to find WinDivert.dll in common locations
        possible_locations = [
            # In the same directory as this package
            package_dir / "WinDivert.dll",
            # In the parent directory (if installed in site-packages)
            package_dir.parent / "WinDivert.dll",
            # In the current working directory
            Path.cwd() / "WinDivert.dll",
        ]
        
        for location in possible_locations:
            if location.exists():
                # Copy to package directory
                shutil.copy2(location, windivert_dll)
                logger.debug(f"Copied WinDivert.dll from {location} to package directory")
                return True
        
        logger.warning("WinDivert.dll not found. Windows local redirect mode may not work.")
        return False
        
    except Exception as e:
        logger.error(f"Failed to ensure WinDivert dependencies: {e}")
        return False


# Setup Windows dependencies if running on Windows
if platform.system() == "Windows":
    _ensure_windivert_dependencies()

# Hacky workaround for https://github.com/PyO3/pyo3/issues/759
for k, v in vars(mitmproxy_rs).items():
    if isinstance(v, types.ModuleType):
        sys.modules[f"mitmproxy_rs.{k}"] = v
