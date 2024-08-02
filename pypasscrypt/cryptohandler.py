"""
# pypasscrypt.cryptohandler
--------------------------

A module to handle encryption/decryption of data using various symmetric and asymmetric encryption methods.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Interfaces:
----------------
- `ISymmetricCryptoHandler`: Interface for handling encryption/decryption and hashing of data.
- `IAsymmetricCryptoHandler`: Interface for handling encryption/decryption for connection between two parties.
- `IHashHandler`: Interface for handling hashing of data.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Types:
----------------
- `SymmetricEncryptionTypes`: Supported symmetric encryption types.
- `AsymmetricEncryptionTypes`: Supported asymmetric encryption types.
- `HashTypes`: Supported hash types.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Exceptions:
----------------
- `InvalidSymmetricEncryptionTypeError`: Exception raised when an invalid symmetric encryption type is provided.
- `InvalidAsymmetricEncryptionTypeError`: Exception raised when an invalid asymmetric encryption type is provided.
- `InvalidHashTypeError`: Exception raised when an invalid hash type is provided.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Classes:
----------------
- `SymmetricCryptoHandler`: A class to handle encryption/decryption of data using symmetric encryption methods.
- `AsymmetricCryptoHandler`: A class to handle encryption/decryption of data using asymmetric encryption methods.
- `HashHandler`: A class to handle hashing of data.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
"""

# Metadata
__version__ = '2.0.0'
__author__ = 'Tejus Gupta'
__email__ = 'tejus3131@gmail.com'
__license__ = 'MIT'
__copyright__ = '2024, Tejus Gupta'
__status__ = 'Development'

# Public API
__all__ = [
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
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    '__status__'
]

import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.modes import CFB
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.base import CipherContext
from cryptography.hazmat.primitives.asymmetric import (
    padding,
    rsa
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey
)
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes
)
from cryptography.hazmat.primitives import (
    hashes,
    serialization
)
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes
)
from abc import (
    ABC,
    abstractmethod
)
from typing import (
    Any,
    Literal,
    Tuple,
    get_args
)


class DecryptionFailedError(Exception):
    """
    # pypasscrypt.cryptohandler.DecryptionFailedError
    ----------------------------------------------

    Exception raised when decryption fails.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, message: str) -> None:
        """
        # pypasscrypt.cryptohandler.DecryptionFailedError.__init__
        ---------------------------------------------------

        Initialize the exception with the provided message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to display.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        super().__init__(message)


# ALl classes and types for symmetric encryption
class ISymmetricCryptoHandler(ABC):
    """
    # pypasscrypt.cryptohandler.ISymmetricCryptoHandler
    -----------------------------------------------

    Interface for handling encryption/decryption and hashing of data.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported methods:
    ------------------
    - `_get_cipher()`: Generate a cipher object using the input string as the key.
    - `encrypt()`: Encrypt data using the provided password.
    - `decrypt()`: Decrypt encrypted data using the provided password.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported classes:
    ------------------
    - `FernetSymmetricCryptoHandler`: Fernet symmetric encryption.
    - `AESSymmetricCryptoHandler`: AES symmetric encryption.
    - `PBKDF2SymmetricCryptoHandler`: Key derivation using PBKDF2 and AES encryption.
    - `ChaCha20SymmetricCryptoHandler`: ChaCha20 symmetric encryption.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    @abstractmethod
    def _get_cipher(*, input_string: str) -> Any:
        """
        # pypasscrypt.cryptohandler.ISymmetricCryptoHandler._get_cipher
        ---------------------------------------------------------
        
        Generate a cipher object using the input string as the key.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `input_string`: The input string to generate the key.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the input string is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        A cipher object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def encrypt(*, data: str, password: str) -> bytes:
        """
        # pypasscrypt.cryptohandler.ISymmetricCryptoHandler.encrypt
        ------------------------------------------------------

        Encrypt the given data using the provided password.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to encrypt.
        - `password`: The password to use for encryption.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the data is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The encrypted data as bytes.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def decrypt(*, encrypted_data: bytes, password: str) -> str:
        """
        # pypasscrypt.cryptohandler.ISymmetricCryptoHandler.decrypt
        ------------------------------------------------------

        Decrypt the given encrypted data using the provided password.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `encrypted_data`: The data to decrypt, as bytes.
        - `password`: The password to use for decryption.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the password is not a string.
        - `DecryptionFailedError`: If decryption fails.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The decrypted data as a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class FernetSymmetricCryptoHandler(ISymmetricCryptoHandler):
    """
    # pypasscrypt.cryptohandler.FernetSymmetricCryptoHandler
    ---------------------------------------------

    A class to handle encryption/decryption of data using Fernet symmetric encryption.

    Supported methods:
    ------------------
    - `_get_cipher()`: Generate a cipher object using the input string as the key.
    - `encrypt()`: Encrypt data using the provided password.
    - `decrypt()`: Decrypt encrypted data using the provided password.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def _get_cipher(*, input_string: str) -> Fernet:
        """
        # pypasscrypt.cryptohandler.FernetSymmetricCryptoHandler._get_cipher
        ---------------------------------------------------------
        
        Generate a cipher object using the input string as the key.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `input_string`: The input string to generate the key.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the input string is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        A cipher object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not isinstance(input_string, str):
            raise TypeError("The input string must be string.")

        hash_digest: bytes = hashlib.sha256(input_string.encode()).digest()
        base64_key: bytes = base64.urlsafe_b64encode(hash_digest[:32])
        return Fernet(base64_key)

    @staticmethod
    def encrypt(*, data: str, password: str) -> bytes:
        """
        # pypasscrypt.cryptohandler.FernetSymmetricCryptoHandler.encrypt
        ------------------------------------------------------

        Encrypt the given data using the provided password.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to encrypt.
        - `password`: The password to use for encryption.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the data is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The encrypted data as bytes.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(data, str):
            raise TypeError("Invalid data")
        
        if not isinstance(password, str):
            raise TypeError("Invalid password")

        cipher: Fernet = FernetSymmetricCryptoHandler._get_cipher(input_string=password)
        encrypted_data: bytes = cipher.encrypt(data.encode())
        return encrypted_data

    @staticmethod
    def decrypt(*, encrypted_data: bytes, password: str) -> str:
        """
        # pypasscrypt.cryptohandler.FernetSymmetricCryptoHandler.decrypt
        ------------------------------------------------------

        Decrypt the given encrypted data using the provided password.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `encrypted_data`: The data to decrypt, as bytes.
        - `password`: The password to use for decryption.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the password is not a string.
        - `DecryptionFailedError`: If decryption fails.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The decrypted data as a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not isinstance(password, str):
            raise TypeError("The password must be a string.")
        
        if not isinstance(encrypted_data, bytes):
            raise TypeError("The encrypted data must be bytes.")

        cipher: Fernet = FernetSymmetricCryptoHandler._get_cipher(input_string=password)
        try:
            decrypted_data: bytes = cipher.decrypt(encrypted_data)
        except Exception as e:
            raise DecryptionFailedError("Decryption failed.") from e
        
        return decrypted_data.decode()


class AESSymmetricCryptoHandler(ISymmetricCryptoHandler):
    """
    # pypasscrypt.cryptohandler.AESSymmetricCryptoHandler
    ------------------------------------------

    A class to handle encryption/decryption of data using AES symmetric encryption.

    Supported methods:
    ------------------
    - `_get_cipher()`: Generate a cipher object using the input string as the key.
    - `encrypt()`: Encrypt data using the provided password.
    - `decrypt()`: Decrypt encrypted data using the provided password.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def _get_cipher(*, input_string: str) -> Tuple[Cipher[CFB], bytes]:
        """
        # pypasscrypt.cryptohandler.AESSymmetricCryptoHandler._get_cipher
        ---------------------------------------------------------
        
        Generate a cipher object using the input string as the key.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `input_string`: The input string to generate the key.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the input string is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        A cipher object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not isinstance(input_string, str):
            raise TypeError("The input string must be string.")

        key: bytes = hashlib.sha256(input_string.encode()).digest()
        iv: bytes = os.urandom(16)
        return Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend()), iv

    @staticmethod
    def encrypt(*, data: str, password: str) -> bytes:
        """
        # pypasscrypt.cryptohandler.AESSymmetricCryptoHandler.encrypt
        ------------------------------------------------------

        Encrypt the given data using the provided password.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to encrypt.
        - `password`: The password to use for encryption.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the data is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The encrypted data as bytes.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(data, str):
            raise TypeError("Invalid data")

        cipher, iv = AESSymmetricCryptoHandler._get_cipher(input_string=password)
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(
            data.encode()) + encryptor.finalize()
        return iv + encrypted_data

    @staticmethod
    def decrypt(*, encrypted_data: bytes, password: str) -> str:
        """
        # pypasscrypt.cryptohandler.AESSymmetricCryptoHandler.decrypt
        ---------------------------------------------------
        ------------------------------------------------------

        Decrypt the given encrypted data using the provided password.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `encrypted_data`: The data to decrypt, as bytes.
        - `password`: The password to use for decryption.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the password is not a string.
        - `DecryptionFailedError`: If decryption fails.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The decrypted data as a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not isinstance(password, str):
            raise TypeError("The password must be a string.") from TypeError(password)
        
        if not isinstance(encrypted_data, bytes):
            raise TypeError("The encrypted data must be bytes.") from TypeError(encrypted_data)

        try:
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            key = hashlib.sha256(password.encode()).digest()
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                            backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(
                ciphertext) + decryptor.finalize()
        except Exception as e:
            raise DecryptionFailedError("Decryption failed.") from e
                
        return decrypted_data.decode()


class PBKDF2SymmetricCryptoHandler(ISymmetricCryptoHandler):
    """
    # pypasscrypt.cryptohandler.PBKDF2SymmetricCryptoHandler
    ----------------------------------------------

    A class to handle key derivation using PBKDF2 and AES encryption.

    Supported methods:
    ------------------
    - `_get_cipher()`: Generate a cipher object using the input string as the key.
    - `encrypt()`: Encrypt data using the provided password.
    - `decrypt()`: Decrypt encrypted data using the provided password.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def _get_cipher(*, input_string: str) -> Tuple[Cipher[CFB], bytes]:
        """
        # pypasscrypt.cryptohandler.PBKDF2SymmetricCryptoHandler._get_cipher
        ---------------------------------------------------------
        
        Generate a cipher object using the input string as the key.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `input_string`: The input string to generate the key.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the input string is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        A cipher object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not isinstance(input_string, str):
            raise TypeError("The input string must be string.")

        salt: bytes = os.urandom(16)
        kdf: PBKDF2HMAC = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key: bytes = kdf.derive(input_string.encode())
        return Cipher(algorithms.AES(key), modes.CFB(salt), backend=default_backend()), salt

    @staticmethod
    def encrypt(*, data: str, password: str) -> bytes:
        """
        # pypasscrypt.cryptohandler.PBKDF2SymmetricCryptoHandler.encrypt
        ------------------------------------------------------

        Encrypt the given data using the provided password.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to encrypt.
        - `password`: The password to use for encryption.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the data is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The encrypted data as bytes.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(data, str):
            raise TypeError("Invalid data")

        cipher_data: Tuple[Cipher[CFB], bytes] = PBKDF2SymmetricCryptoHandler._get_cipher(
            input_string=password)
        cipher: Cipher[CFB] = cipher_data[0]
        salt: bytes = cipher_data[1]
        encryptor: CipherContext = cipher.encryptor()
        encrypted_data: bytes = encryptor.update(
            data.encode()) + encryptor.finalize()
        return salt + encrypted_data

    @staticmethod
    def decrypt(*, encrypted_data: bytes, password: str) -> str:
        """
        # pypasscrypt.cryptohandler.PBKDF2SymmetricCryptoHandler.decrypt
        ------------------------------------------------------
        ------------------------------------------------------

        Decrypt the given encrypted data using the provided password.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `encrypted_data`: The data to decrypt, as bytes.
        - `password`: The password to use for decryption.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the password is not a string.
        - `DecryptionFailedError`: If decryption fails.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The decrypted data as a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not isinstance(password, str):
            raise TypeError("The password must be a string.")
        
        if not isinstance(encrypted_data, bytes):
            raise TypeError("The encrypted data must be bytes.")

        try:
            salt: bytes = encrypted_data[:16]
            ciphertext: bytes = encrypted_data[16:]
            kdf: PBKDF2HMAC = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key: bytes = kdf.derive(password.encode())
            cipher: Cipher = Cipher(algorithms.AES(key), modes.CFB(
                salt), backend=default_backend())
            decryptor: CipherContext = cipher.decryptor()
            decrypted_data: bytes = decryptor.update(
                ciphertext) + decryptor.finalize()
        except Exception as e:
            raise DecryptionFailedError("Decryption failed.") from e
                
        return decrypted_data.decode()


class ChaCha20SymmetricCryptoHandler(ISymmetricCryptoHandler):
    """
    # pypasscrypt.cryptohandler.ChaCha20SymmetricCryptoHandler
    -----------------------------------------------

    A class to handle encryption/decryption of data using ChaCha20 symmetric encryption.

    Supported methods:
    ------------------
    - `_get_cipher()`: Generate a cipher object using the input string as the key.
    - `encrypt()`: Encrypt data using the provided password.
    - `decrypt()`: Decrypt encrypted data using the provided password.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def _get_cipher(*, input_string: str) -> Tuple[Cipher[None], bytes]:
        """
        # pypasscrypt.cryptohandler.ChaCha20SymmetricCryptoHandler._get_cipher
        ----------------------------------------------------------
        ---------------------------------------------------------
        
        Generate a cipher object using the input string as the key.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `input_string`: The input string to generate the key.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the input string is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        A cipher object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not isinstance(input_string, str):
            raise TypeError("The input string must be string.")

        key: bytes = hashlib.sha256(input_string.encode()).digest()
        nonce: bytes = os.urandom(16)
        return Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend()), nonce

    @staticmethod
    def encrypt(*, data: str, password: str) -> bytes:
        """
        # pypasscrypt.cryptohandler.ChaCha20SymmetricCryptoHandler.encrypt
        ------------------------------------------------------

        Encrypt the given data using the provided password.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to encrypt.
        - `password`: The password to use for encryption.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the data is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The encrypted data as bytes.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(data, str):
            raise TypeError("Invalid data")

        cipher_data: Tuple[Cipher[None], bytes] = ChaCha20SymmetricCryptoHandler._get_cipher(
            input_string=password)
        cipher: Cipher[None] = cipher_data[0]
        nonce: bytes = cipher_data[1]
        encryptor: CipherContext = cipher.encryptor()
        encrypted_data: bytes = encryptor.update(data.encode())
        return nonce + encrypted_data

    @staticmethod
    def decrypt(*, encrypted_data: bytes, password: str) -> str:
        """
        # pypasscrypt.cryptohandler.ChaCha20SymmetricCryptoHandler.decrypt
        --------------------------------------------------------
        ------------------------------------------------------

        Decrypt the given encrypted data using the provided password.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `encrypted_data`: The data to decrypt, as bytes.
        - `password`: The password to use for decryption.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the password is not a string.
        - `DecryptionFailedError`: If decryption fails.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The decrypted data as a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not isinstance(password, str):
            raise TypeError("The password must be a string.")
        
        if not isinstance(encrypted_data, bytes):
            raise TypeError("The encrypted data must be bytes.")

        try:
            nonce: bytes = encrypted_data[:16]
            ciphertext: bytes = encrypted_data[16:]
            key: bytes = hashlib.sha256(password.encode()).digest()
            cipher: Cipher = Cipher(algorithms.ChaCha20(key, nonce),
                                    mode=None, backend=default_backend())
            decryptor: CipherContext = cipher.decryptor()
            decrypted_data: bytes = decryptor.update(ciphertext)
        except Exception as e:
            raise DecryptionFailedError("Decryption failed.") from e
                
        return decrypted_data.decode()


SymmetricEncryptionTypes = Literal["Fernet", "AES", "PBKDF2", "ChaCha20"]
"""
# pypasscrypt.cryptohandler.SymmetricEncryptionTypes
--------------------------------------------------

Supported symmetric encryption types.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Values:
------
- `Fernet`
- `AES`
- `PBKDF2`
- `ChaCha20`

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
"""


class InvalidSymmetricEncryptionTypeError(Exception):
    """
    # pypasscrypt.cryptohandler.InvalidSymmetricEncryptionTypeError
    --------------------------------------------------------

    Exception raised when an invalid symmetric encryption type is provided.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, message: str) -> None:
        """
        # pypasscrypt.cryptohandler.InvalidSymmetricEncryptionTypeError.__init__
        ----------------------------------------------------------

        Initialize the exception with the provided message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to display.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        super().__init__(message)


class SymmetricCryptoHandler:
    """
    # pypasscrypt.cryptohandler.SymmetricCryptoHandler
    ------------------------------------------------

    A class to handle encryption/decryption of data using various symmetric and asymmetric encryption methods.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported types:
    ----------------
    - `Fernet`: Fernet symmetric encryption.
    - `AES`: AES symmetric encryption.
    - `PBKDF2`: Key derivation using PBKDF2 and AES encryption.
    - `ChaCha20`: ChaCha20 symmetric encryption.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Methods:
    --------
    - `encrypt()`: Encrypt data using the provided password and encryption method.
    - `decrypt()`: Decrypt encrypted data using the provided password and encryption method.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def encrypt(
            *,
            data: str,
            password: str,
            method: SymmetricEncryptionTypes
    ) -> bytes:
        """
        # pypasscrypt.cryptohandler.SymmetricCryptoHandler.encrypt
        --------------------------------------------------------

        Encrypt the given data using the provided password and encryption method.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Supported types:
        ----------------
        - `Fernet`: Fernet symmetric encryption.
        - `AES`: AES symmetric encryption.
        - `PBKDF2`: Key derivation using PBKDF2 and AES encryption.
        - `ChaCha20`: ChaCha20 symmetric encryption.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to encrypt.
        - `password`: The password to use for encryption.
        - `method`: The encryption method to use.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: if parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The encrypted data as bytes.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(data, str):
            raise TypeError("Invalid data")
        
        if not isinstance(password, str):
            raise TypeError("Invalid password")
        
        if method not in get_args(SymmetricEncryptionTypes):
            raise InvalidSymmetricEncryptionTypeError(
                message="Unsupported symmetric encryption method.") from TypeError(method)

        if method == "Fernet":
            return FernetSymmetricCryptoHandler.encrypt(
                data=data,
                password=password
            )
        elif method == "AES":
            return AESSymmetricCryptoHandler.encrypt(
                data=data,
                password=password
            )
        elif method == "PBKDF2":
            return PBKDF2SymmetricCryptoHandler.encrypt(
                data=data,
                password=password
            )
        elif method == "ChaCha20":
            return ChaCha20SymmetricCryptoHandler.encrypt(
                data=data,
                password=password
            )

    @staticmethod
    def decrypt(
            *,
            encrypted_data: bytes,
            password: str,
            method: SymmetricEncryptionTypes
    ) -> str:
        """
        # pypasscrypt.cryptohandler.SymmetricCryptoHandler.decrypt
        --------------------------------------------------------

        Decrypt the given encrypted data using the provided password and encryption method.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Supported types:
        ----------------
        - `Fernet`: Fernet symmetric encryption.
        - `AES`: AES symmetric encryption.
        - `PBKDF2`: Key derivation using PBKDF2 and AES encryption.
        - `ChaCha20`: ChaCha20 symmetric encryption.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `encrypted_data`: The data to decrypt, as bytes.
        - `password`: The password to use for decryption.
        - `method`: The encryption method to use.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the password is not a string, the encrypted data is not bytes, or the method is not supported.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The decrypted data as a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(encrypted_data, bytes):
            raise TypeError("Invalid data")
        
        if not isinstance(password, str):
            raise TypeError("Invalid password")
        
        if method not in get_args(SymmetricEncryptionTypes):
            raise InvalidSymmetricEncryptionTypeError(
                message="Unsupported symmetric encryption method.") from TypeError(method)

        if method == "Fernet":
            return FernetSymmetricCryptoHandler.decrypt(
                encrypted_data=encrypted_data,
                password=password
            )
        elif method == "AES":
            return AESSymmetricCryptoHandler.decrypt(
                encrypted_data=encrypted_data,
                password=password
            )
        elif method == "PBKDF2":
            return PBKDF2SymmetricCryptoHandler.decrypt(
                encrypted_data=encrypted_data,
                password=password
            )
        elif method == "ChaCha20":
            return ChaCha20SymmetricCryptoHandler.decrypt(
                encrypted_data=encrypted_data,
                password=password
            )


# All classes and types for asymmetric encryption
class IAsymmetricCryptoHandler(ABC):
    """
    # pypasscrypt.cryptohandler.IAsymmetricCryptoHandler
    --------------------------------------------------

    Interface for handling encryption/decryption for connection between two parties.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported methods:
    ------------------
    - `generate_keys()`: Generate a new private-public key pair.
    - `encrypt()`: Encrypt data using the provided public key.
    - `decrypt()`: Decrypt encrypted data using the provided private key.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported classes:
    ------------------
    - `RSAAsymmetricCryptoHandler`: RSA asymmetric encryption.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    @abstractmethod
    def generate_keys() -> Tuple[bytes, bytes]:
        """
        # pypasscrypt.cryptohandler.IAsymmetricCryptoHandler.generate_keys
        -----------------------------------------------------------------

        Generate a new private-public key pair.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        A tuple containing the private key and public key in PEM format.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def encrypt(*, data: str, public_key_pem: bytes) -> bytes:
        """
        # pypasscrypt.cryptohandler.IAsymmetricCryptoHandler.encrypt
        ----------------------------------------------------------

        Encrypt the given data using the provided public key.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to encrypt.
        - `public_key_pem`: The public key in PEM format.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the json_data is not a dictionary or if the public_key_pem is not bytes.
        - `ValueError`: If the public key is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        Encrypted data as bytes.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def decrypt(*, encrypted_data: bytes, private_key_pem: bytes) -> str:
        """
        # pypasscrypt.cryptohandler.IAsymmetricCryptoHandler.decrypt
        --------------------------------------------------

        Decrypt the given encrypted data using the provided private key.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `encrypted_data`: The data to decrypt, as bytes.
        - `private_key_pem`: The private key in PEM format.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the private_key_pem is not bytes.
        - `ValueError`: If the private key is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The decrypted data as a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class RSAAsymmetricCryptoHandler(IAsymmetricCryptoHandler):
    """
    # pypasscrypt.cryptohandler.RSAAsymmetricCryptoHandler
    ------------------------------------------

    A class to handle encryption/decryption of data using RSA asymmetric encryption.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported methods:
    ------------------
    - `generate_keys()`: Generate a new private-public key pair.
    - `encrypt()`: Encrypt data using the provided public key.
    - `decrypt()`: Decrypt encrypted data using the provided private key.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def generate_keys() -> Tuple[bytes, bytes]:
        """
        # pypasscrypt.cryptohandler.RSAAsymmetricCryptoHandler.generate_keys
        -----------------------------------------------------------------

        Generate a new private-public key pair.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        A tuple containing the private key and public key in PEM format.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        private_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key: RSAPublicKey = private_key.public_key()

        private_pem: bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem: bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    @staticmethod
    def encrypt(*, data: str, public_key_pem: bytes) -> bytes:
        """
        # pypasscrypt.cryptohandler.RSAAsymmetricCryptoHandler.encrypt
        --------------------------------------------------

        Encrypt the given data using the provided RSA public key.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `json_data`: The data to encrypt, as a dictionary.
        - `public_key_pem`: The RSA public key in PEM format.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the json_data is not a dictionary or if the public_key_pem is not bytes.
        - `ValueError`: If the public key is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        Encrypted data as bytes.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(data, str):
            raise TypeError("Invalid data") from ValueError(data)
        
        if not isinstance(public_key_pem, bytes):
            raise TypeError("Invalid public_key_pem") from ValueError(public_key_pem)

        public_key: PublicKeyTypes = serialization.load_pem_public_key(
            public_key_pem, backend=default_backend())
        
        if not isinstance(public_key, RSAPublicKey):
            raise ValueError("Invalid RSA public key.") from ValueError(public_key)

        encrypted_data = public_key.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_data

    @staticmethod
    def decrypt(*, encrypted_data: bytes, private_key_pem: bytes) -> str:
        """
        # pypasscrypt.cryptohandler.RSAAsymmetricCryptoHandler.decrypt
        --------------------------------------------------

        Decrypt the given encrypted data using the provided RSA private key.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `encrypted_data`: The data to decrypt, as bytes.
        - `private_key_pem`: The private key in PEM format.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the private_key_pem is not bytes.
        - `ValueError`: If the private key is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The decrypted data as a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(private_key_pem, bytes):
            raise TypeError("Invalid private_key_pem")
        
        if not isinstance(encrypted_data, bytes):
            raise TypeError("Invalid encrypted_data")

        private_key: PrivateKeyTypes = serialization.load_pem_private_key(
            private_key_pem, password=None, backend=default_backend())
        if not isinstance(private_key, RSAPrivateKey):
            raise ValueError("Invalid RSA private key.")
        
        try:
            decrypted_data = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            raise DecryptionFailedError("Decryption failed.") from e
        
        return decrypted_data.decode()
    

AsymmetricEncryptionTypes = Literal["RSA"]
"""
# pypasscrypt.cryptohandler.AsymmetricEncryptionTypes
--------------------------------------------------

Supported asymmetric encryption types.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Values:
------
- `RSA`

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
"""


class InvalidAsymmetricEncryptionTypeError(Exception):
    """
    # pypasscrypt.cryptohandler.InvalidAsymmetricEncryptionTypeError
    --------------------------------------------------------

    Exception raised when an invalid asymmetric encryption type is provided.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, message: str) -> None:
        """
        # pypasscrypt.cryptohandler.InvalidAsymmetricEncryptionTypeError.__init__
        ----------------------------------------------------------

        Initialize the exception with the provided message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to display.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        super().__init__(message)


class AsymmetricCryptoHandler:
    """
    # pypasscrypt.cryptohandler.AsymmetricCryptoHandler
    -------------------------------------------------

    A class to handle encryption/decryption of data using various asymmetric encryption methods.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported types:
    ---------------
    - `RSA`: RSA asymmetric encryption.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Methods:
    -------
    - `generate_keys()`: Generate a new private-public key pair.
    - `encrypt()`: Encrypt data using the provided public key and encryption method.
    - `decrypt()`: Decrypt encrypted data using the provided private key and encryption method.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def generate_keys(method: AsymmetricEncryptionTypes) -> Tuple[bytes, bytes]:
        """
        # pypasscrypt.cryptohandler.AsymmetricCryptoHandler.generate_keys
        -----------------------------------------------------------------

        Generate a new private-public key pair using the provided encryption method.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Supported types:
        ---------------
        - `RSA`: RSA asymmetric encryption.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `method`: The encryption method to use.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `InvalidAsymmetricEncryptionTypeError`: If the method is not supported.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        A tuple containing the private key and public key in PEM format.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if method not in get_args(AsymmetricEncryptionTypes):
            raise InvalidAsymmetricEncryptionTypeError(
                message="Unsupported asymmetric encryption method.") from TypeError(method)

        if method == "RSA":
            return RSAAsymmetricCryptoHandler.generate_keys()

    @staticmethod
    def encrypt(*, data: str, public_key_pem: bytes,
                method: AsymmetricEncryptionTypes) -> bytes:
        """
        # pypasscrypt.cryptohandler.AsymmetricCryptoHandler.encrypt
        --------------------------------------------------------
        
        Encrypt the given data using the provided public key and encryption method.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Supported types:
        ---------------
        - `RSA`: RSA asymmetric encryption.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to encrypt.
        - `public_key_pem`: The public key in PEM format.
        - `method`: The encryption method to use.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the public_key_pem is not bytes or the method is not supported.
        - `InvalidAsymmetricEncryptionTypeError`: If the method is not supported.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        Encrypted data as bytes.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        
        if not isinstance(public_key_pem, bytes):
            raise TypeError("Invalid public_key_pem")
        
        if method not in get_args(AsymmetricEncryptionTypes):
            raise InvalidAsymmetricEncryptionTypeError(
                message="Unsupported asymmetric encryption method.") from TypeError(method)

        if method == "RSA":
            return RSAAsymmetricCryptoHandler.encrypt(
                data=data,
                public_key_pem=public_key_pem
            )

    @staticmethod
    def decrypt(
            *,
            encrypted_data: bytes,
            private_key_pem: bytes,
            method: AsymmetricEncryptionTypes
    ) -> str:
        """
        # pypasscrypt.cryptohandler.AsymmetricCryptoHandler.decrypt
        --------------------------------------------------------

        Decrypt the given encrypted data using the provided private key and encryption method.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Supported types:
        ---------------
        - `RSA`: RSA asymmetric encryption.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `encrypted_data`: The data to decrypt, as bytes.
        - `private_key_pem`: The private key in PEM format.
        - `method`: The encryption method to use.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the private_key_pem is not bytes or the method is not supported.
        - `InvalidAsymmetricEncryptionTypeError`: If the method is not supported.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The decrypted data as a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(private_key_pem, bytes):
            raise TypeError("Invalid private_key_pem")
        
        if not isinstance(encrypted_data, bytes):
            raise TypeError("Invalid encrypted_data")
        
        if method not in get_args(AsymmetricEncryptionTypes):
            raise InvalidAsymmetricEncryptionTypeError(
                message="Unsupported asymmetric encryption method.") from TypeError(method)

        if method == "RSA":
            return RSAAsymmetricCryptoHandler.decrypt(
                encrypted_data=encrypted_data,
                private_key_pem=private_key_pem
            )


# All classes and types for hashing

class IHashHandler(ABC):
    """
    # pypasscrypt.hashhandler.IHashHandler
    -------------------------------------

    Interface for handling hashing of data.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported methods:
    ------------------
    - `generate_hash()`: Hash the given data.
    - `verify_hash()`: Verify the given data.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported classes:
    ------------------
    - `SHA256HashHandler`: SHA-256 hashing.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    @abstractmethod
    def generate_hash(*, data: str) -> str:
        """
        # pypasscrypt.hashhandler.IHashHandler.hash
        ------------------------------------------

        Hash the given data.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to hash.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The hashed data as a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def verify_hash(*, data: str, hash_data: str) -> bool:
        """
        # pypasscrypt.hashhandler.IHashHandler.verify_hash
        -------------------------------------------------

        Verify the given data.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to verify.
        - `hash_data`: The hash to verify against.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        True if the data matches the hash, False otherwise.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    
class SHA256HashHandler(IHashHandler):
    """
    # pypasscrypt.hashhandler.SHA256HashHandler
    ------------------------------------------

    A class to handle hashing of data using SHA-256.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported methods:
    ------------------
    - `generate_hash()`: Hash the given data.
    - `verify_hash()`: Verify the given data.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def generate_hash(*, data: str) -> str:
        """
        # pypasscrypt.hashhandler.SHA256HashHandler.generate_hash
        --------------------------------------------------------

        Hash the given data using SHA-256.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to hash.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The hashed data as a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(data, str):
            raise TypeError("Invalid data")

        hasher = hashlib.sha256()
        hasher.update(data.encode())
        return hasher.hexdigest()
    
    @staticmethod
    def verify_hash(*, data: str, hash_data: str) -> bool:
        """
        # pypasscrypt.hashhandler.SHA256HashHandler.verify_hash
        ------------------------------------------------------

        Verify the given data using the hash.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to verify.
        - `hash_data`: The hash to verify against.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        True if the data matches the hash, False otherwise.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(data, str):
            raise TypeError("Invalid data")
        
        if not isinstance(hash_data, str):
            raise TypeError("Invalid hash")

        return SHA256HashHandler.generate_hash(data=data) == hash_data
    

HashTypes = Literal["SHA256"]
"""
# pypasscrypt.hashhandler.HashTypes
-----------------------------------

Supported hash types.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Values:
------
- `SHA256`

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
"""


class InvalidHashTypeError(Exception):
    """
    # pypasscrypt.hashhandler.InvalidHashTypeError
    ----------------------------------------

    Exception raised when an invalid hash type is provided.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, message: str) -> None:
        """
        # pypasscrypt.hashhandler.InvalidHashTypeError.__init__
        ------------------------------------------------

        Initialize the exception with the provided message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to display.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        super().__init__(message)


class HashHandler:
    """
    # pypasscrypt.hashhandler.HashHandler
    -------------------------------------

    A class to handle hashing of data using various hash methods.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported types:
    ----------------
    - `SHA256`: SHA-256 hashing.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Methods:
    --------
    - `generate_hash()`: Hash the given data using the provided hash method.
    - `verify_hash()`: Verify the given data using the provided hash method.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def generate_hash(*, data: str, method: HashTypes) -> str:
        """
        # pypasscrypt.hashhandler.HashHandler.generate_hash
        --------------------------------------------------

        Hash the given data using the provided hash method.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Supported types:
        ----------------
        - `SHA256`: SHA-256 hashing.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to hash.
        - `method`: The hash method to use.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the data is not a string or the method is not supported.
        - `InvalidHashTypeError`: If the method is not supported.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        The hashed data as a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(data, str):
            raise TypeError("Invalid data")
        
        if method not in get_args(HashTypes):
            raise InvalidHashTypeError(message="Unsupported hash method.") from TypeError(method)

        if method == "SHA256":
            return SHA256HashHandler.generate_hash(data=data)

    @staticmethod
    def verify_hash(*, data: str, hash_data: str, method: HashTypes) -> bool:
        """
        # pypasscrypt.hashhandler.HashHandler.verify_hash
        ------------------------------------------------

        Verify the given data using the hash method.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Supported types:
        ----------------
        - `SHA256`: SHA-256 hashing.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to verify.
        - `hash_data`: The hash to verify against.
        - `method`: The hash method to use.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the data is not a string, the hash is not a string, or the method is not supported.
        - `InvalidHashTypeError`: If the method is not supported.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        ---------
        True if the data matches the hash, False otherwise.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(data, str):
            raise TypeError("Invalid data")
        
        if not isinstance(hash_data, str):
            raise TypeError("Invalid hash")
        
        if method not in get_args(HashTypes):
            raise InvalidHashTypeError(message="Unsupported hash method.") from TypeError(method)

        if method == "SHA256":
            return SHA256HashHandler.verify_hash(data=data, hash_data=hash_data)
