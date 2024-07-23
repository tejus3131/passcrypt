"""
Password Manager package.

This module provides various utility classes and constants for password management,
encryption, and storage.
"""

# Utility classes
from pypasscrypt.passcrypt import (
    UserInterface,  # User Interface class for command line interface.
    Storage,  # Storage class for managing storage of passwords.
    CryptoHandler,  # CryptoHandler class for encryption and decryption.
    PasswordGenerator,  # PasswordGenerator class for generating passwords.
    PasswordManager  # PasswordManager class for managing passwords.
)

# Password Generation
from pypasscrypt.passcrypt import (
    SIMILAR_CHARS,  # Similar characters to avoid in password generation.
    CONTEXT_FILTER  # Context filter for password generation.
)

# Constants
from pypasscrypt.passcrypt import (
    EXTENSION,  # File extension for storage files.
    EXPORT_DIRECTORY,  # Export directory for storage files.
    APPLICATION_NAME,  # Application name for storage files.
    DIRECTORY,  # Directory for storage files.
    FILENAME,  # Filename for storage files.
    DOWNLOADS,  # Downloads directory for storage files.
    PATHS  # Paths for storage files.
)

# Public API
__all__ = [
    'UserInterface',
    'Storage',
    'CryptoHandler',
    'PasswordGenerator',
    'PasswordManager',
    'SIMILAR_CHARS',
    'CONTEXT_FILTER',
    'EXTENSION',
    'EXPORT_DIRECTORY',
    'APPLICATION_NAME',
    'DIRECTORY',
    'FILENAME',
    'DOWNLOADS',
    'PATHS',
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    '__url__',
    '__description__',
    '__name__',
    '__package__',
    '__title__',
    '__summary__',
    '__keywords__',
    '__classifiers__'
]

# Metadata
__version__ = '1.0.1'
__author__ = "Tejus Gupta"
__email__ = "tejus3131@gmail.com"
__license__ = "MIT"
__url__ = "https://github.com/tejus3131/passcrypt"
__description__ = "Password Manager package."
__name__ = "pypasscrypt"
__package__ = "pypasscrypt"
__title__ = "pypasscrypt"
__summary__ = "Password Manager package."
__keywords__ = "password manager"
__classifiers__ = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Operating System :: OS Independent",
    "Topic :: Security",
    "Topic :: Security :: Cryptography",
    "Topic :: Security :: Password Manager",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: Utilities",
]

# Ensure no duplicates in __all__
__all__ = list(set(__all__))
print(__all__)