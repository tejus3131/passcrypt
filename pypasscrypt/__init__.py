"""
# pypasscrypt
-----------

PassCrypt is a comprehensive package and command-line tool designed to securely manage your passwords.
It includes various submodules for configuration, connection handling, cryptographic operations,
logging, password management, storage, and user interface components.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Submodules:
-----------
- `connection`: Protocols for PassCrypt connections.
- `cryptohandler`: Symmetric and asymmetric cryptographic handlers.
- `logging`: Logging utilities.
- `passwordmanager`: Interfaces and implementations for password management.
- `storage`: Enhanced Password Container (EPC) for secure storage.
- `userinterface`: Components for creating user interfaces, including display and input components.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Public API:
-----------
- connection:

    - Interfaces:
        - `IConnectionProtocolHandler`: Interface for connection protocol handlers.

    - Types:
        - `ConnectionProtocolTypes`: Connection protocol types.

    - Exceptions:
        - `InvalidConnectionProtocolError`: Invalid connection protocol error.

    - Classes:
        - `ConnectionProtocolHandler`: Connection protocol handler.

- cryptohandler:

    - Interfaces:
        - `ISymmetricCryptoHandler`: Interface for symmetric cryptographic handlers.
        - `IAsymmetricCryptoHandler`: Interface for asymmetric cryptographic handlers.
        - `IHashHandler`: Interface for hash handlers.

    - Types:
        - `SymmetricEncryptionTypes`: Symmetric encryption types.
        - `AsymmetricEncryptionTypes`: Asymmetric encryption types.
        - `HashTypes`: Hash types.

    - Exceptions:
        - `DecryptionFailedError`: Decryption failed error.
        - `InvalidSymmetricEncryptionTypeError`: Invalid symmetric encryption type error.
        - `InvalidAsymmetricEncryptionTypeError`: Invalid asymmetric encryption type error.
        - `InvalidHashTypeError`: Invalid hash type error.

    - Classes:
        - `SymmetricCryptoHandler`: Symmetric cryptographic handler.
        - `AsymmetricCryptoHandler`: Asymmetric cryptographic handler.
        - `HashHandler`: Hash handler.

- passwordmanager:

    - Interfaces:
        - `IPasswordManagerHandler`: Interface for password manager handlers.

    - Types:
        - `PasswordManagerTypes`: Password manager types.

    - Exceptions:
        - `InvalidPasswordManagerTypeError`: Invalid password manager type error.

    - Classes:
        - `PasswordManagerHandler`: Password manager handler.

- storage:

    - Types:
        - `PasswordBucket`: Password bucket datatype.

    - Exceptions:
        - `InvalidPasswordBucketError`: Invalid password bucket error.
        - `InvalidEPCFileError`: Invalid EPC file error.
        - `InvalidEPTFileError`: Invalid EPT file error.

    - Classes:
        - `EPC`: Enhanced Password Container (EPC) class.
        - `EPT`: Enhanced Password Table (EPT) class.

- userinterface:
    
    - Interfaces:
        - `IUIComponent`: Interface for UI components.
        - `IUIDisplayComponent`: Interface for UI display components.
        - `IUIInputComponent`: Interface for UI input components.

    - Types:
        - `DisplayStyle`: Display style.

    - Exceptions:
        - `InvalidDisplayStyleError`: Invalid display style error.

    - Classes:
        - `UI`: User interface class.
        - `UIPanelDisplay`: Panel display class.
        - `UIMessageDisplay`: Message display class.
        - `UINotificationDisplay`: Notification display class.
        - `UITableDisplay`: Table display class.
        - `UITextInput`: Text input class.
        - `UISingleSelectionInput`: Single selection input class.
        - `UIMultiSelectionInput`: Multi selection input class.
        - `UIConfirmInput`: Confirm input class.
        - `UITextSuggestionInput`: Text suggestion input class.
        - `UIPasswordInput`: Password input class.
        - `UINewPasswordInput`: New password input class.
        - `UIMasterPasswordInput`: Master password input class.
        - `UINewMasterPasswordInput`: New master password input class.
        - `UIFileInput`: File input class.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
"""

# Importing public apis submodules
from pypasscrypt.connectionhandler import (
    IConnectionProtocolHandler,
    ConnectionProtocolTypes,
    InvalidConnectionProtocolError,
    ConnectionProtocolHandler
)
from pypasscrypt.cryptohandler import (
    DecryptionFailedError,
    ISymmetricCryptoHandler,
    SymmetricEncryptionTypes,
    InvalidSymmetricEncryptionTypeError,
    SymmetricCryptoHandler,
    IAsymmetricCryptoHandler,
    AsymmetricEncryptionTypes,
    InvalidAsymmetricEncryptionTypeError,
    AsymmetricCryptoHandler,
    IHashHandler,
    HashTypes,
    InvalidHashTypeError,
    HashHandler
)
from pypasscrypt.passwordhandler import (
    PasswordStrength,
    IPasswordManagerHandler,
    PasswordManagerTypes,
    InvalidPasswordManagerTypeError,
    PasswordManagerHandler
)
from pypasscrypt.storagehandler import (
    InvalidPasswordBucketError,
    InvalidEPCFileError,
    InvalidEPTFileError,
    PasswordBucket,
    EPC,
    EPT
)
from pypasscrypt.userinterface import (
    IUIComponent,
    IUIDisplayComponent,
    IUIInputComponent,
    DisplayStyle,
    InvalidDisplayStyleError,
    UI,
    UIPanelDisplay,
    UIMessageDisplay,
    UINotificationDisplay,
    UITableDisplay,
    UITextInput,
    UISingleSelectionInput,
    UIMultiSelectionInput,
    UIConfirmInput,
    UITextSuggestionInput,
    UIPasswordInput,
    UINewPasswordInput,
    UIMasterPasswordInput,
    UINewMasterPasswordInput,
    UIFileInput
)

from pypasscrypt import (
    connectionhandler,
    cryptohandler,
    passwordhandler,
    storagehandler,
    userinterface
)

# Metadata
__version__ = '2.0.0'
__author__ = "Tejus Gupta"
__email__ = "tejus3131@gmail.com"
__license__ = "MIT"
__url__ = "https://github.com/tejus3131/passcrypt"
__description__ = "PassCrypt is a package that provide everything you need to create your own password manager."
__name__ = "pypasscrypt"
__package__ = "pypasscrypt"
__title__ = "pypasscrypt"
__summary__ = "PassCrypt is a package that provide everything you need to create your own password manager."
__keywords__ = [
    "password manager",
    "encryption",
    "storage",
    "security",
    "cli",
    "passcrypt",
    "pypasscrypt"
]
__copyright__ = '2024, Tejus Gupta'
__status__ = 'Development'
__classifiers__ = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Topic :: Security",
    "Topic :: Security :: Cryptography",
    "Topic :: Security :: Password Managers",
    "Topic :: Software Development :: Libraries",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: Utilities",
    "Typing :: Typed"
]

# Public API
__all__ = [
    'connectionhandler',
    'IConnectionProtocolHandler',
    'ConnectionProtocolTypes',
    'InvalidConnectionProtocolError',
    'ConnectionProtocolHandler',
    'cryptohandler',
    'DecryptionFailedError',
    'ISymmetricCryptoHandler',
    'SymmetricEncryptionTypes',
    'InvalidSymmetricEncryptionTypeError',
    'SymmetricCryptoHandler',
    'IAsymmetricCryptoHandler',
    'AsymmetricEncryptionTypes',
    'InvalidAsymmetricEncryptionTypeError',
    'AsymmetricCryptoHandler',
    'IHashHandler',
    'HashTypes',
    'InvalidHashTypeError',
    'HashHandler',
    'passwordhandler',
    'PasswordStrength',
    'IPasswordManagerHandler',
    'PasswordManagerTypes',
    'InvalidPasswordManagerTypeError',
    'PasswordManagerHandler',
    'storagehandler',
    'InvalidPasswordBucketError',
    'InvalidEPCFileError',
    'InvalidEPTFileError',
    'PasswordBucket',
    'EPC',
    'EPT',
    'userinterface',
    'IUIComponent',
    'IUIDisplayComponent',
    'IUIInputComponent',
    'DisplayStyle',
    'InvalidDisplayStyleError',
    'UI',
    'UIPanelDisplay',
    'UIMessageDisplay',
    'UINotificationDisplay',
    'UITableDisplay',
    'UITextInput',
    'UISingleSelectionInput',
    'UIMultiSelectionInput',
    'UIConfirmInput',
    'UITextSuggestionInput',
    'UIPasswordInput',
    'UINewPasswordInput',
    'UIMasterPasswordInput',
    'UINewMasterPasswordInput',
    'UIFileInput',
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
    '__copyright__',
    '__status__',
    '__classifiers__'
]
