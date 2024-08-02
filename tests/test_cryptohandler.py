"""
pypasscrypt.cryptohandler
--------------------------

A module to handle encryption/decryption of data using various symmetric and asymmetric encryption methods.

Interfaces:
----------------
- `ISymmetricCryptoHandler`: Interface for handling encryption/decryption and hashing of data.
- `IAsymmetricCryptoHandler`: Interface for handling encryption/decryption for connection between two parties.
- `IHashing`: Interface for handling hashing of data.

Types:
----------------
- `SymmetricEncryptionTypes`: Supported symmetric encryption types.
- `AsymmetricEncryptionTypes`: Supported asymmetric encryption types.

Classes:
----------------
- `FernetCryptoHandler`: A class to handle encryption/decryption of data using Fernet symmetric encryption.
- `AESCryptoHandler`: A class to handle encryption/decryption of data using AES symmetric encryption.
- `PBKDF2CryptoHandler`: A class to handle key derivation using PBKDF2 and AES encryption.
- `ChaCha20CryptoHandler`: A class to handle encryption/decryption of data using ChaCha20 symmetric encryption.
- `SymmetricCryptoHandler`: A class to handle encryption/decryption of data using symmetric encryption methods.
- `RSACryptoHandler`: A class to handle encryption/decryption of data using RSA asymmetric encryption.
- `AsymmetricCryptoHandler`: A class to handle encryption/decryption of data using asymmetric encryption methods.
- `Hashing`: A class to handle hashing of data using various hashing methods.

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
    'ISymmetricCryptoHandler',
    'IAsymmetricCryptoHandler',
    'IHashing',
    'SymmetricEncryptionTypes',
    'AsymmetricEncryptionTypes',
    'SymmetricCryptoHandler',
    'AsymmetricCryptoHandler',
    'Hashing',
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    '__status__'
]

import os
import json
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
    PublicKeyTypes,
)
from abc import (
    ABC,
    abstractmethod
)
from typing import (
    Dict,
    Any,
    Literal,
    Tuple,
    Union
)


class ISymmetricCryptoHandler(ABC):
    """
    pypasscrypt.cryptohandler.ISymmetricCryptoHandler
    -----------------------------------------------

    Interface for handling encryption/decryption and hashing of data.

    Supported methods:
    ------------------
    - `_get_cipher()`: Generate a cipher object using the input string as the key.
    - `encrypt()`: Encrypt data using the provided password.
    - `decrypt()`: Decrypt encrypted data using the provided password.

    Supported classes:
    ------------------
    - `FernetCryptoHandler`: Fernet symmetric encryption.
    - `AESCryptoHandler`: AES symmetric encryption.
    - `PBKDF2CryptoHandler`: Key derivation using PBKDF2 and AES encryption.
    - `ChaCha20CryptoHandler`: ChaCha20 symmetric encryption.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    @abstractmethod
    def _get_cipher(*, input_string: str) -> Any:
        """
        pyppasscrypt.cryptohandler.ISymmetricCryptoHandler._get_cipher
        ----------------------------------------------------------------

        Generate a cipher object using the input string as the key.

        :param input_string: The input string to generate the key.
        :return: Any cipher object.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def encrypt(*, data: Union[Dict[str, Dict[str, str]], str], password: str) -> bytes:
        """
        pyppasscrypt.cryptohandler.ISymmetricCryptoHandler.encrypt
        ----------------------------------------------------------

        Encrypt the given data using the provided password.

        :param data: The data to encrypt, as a dictionary or string.
        :param password: The password to use for encryption.
        :return: Encrypted data as bytes.
        :raises ValueError: If the password is empty.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def decrypt(*, encrypted_data: bytes, password: str) -> Union[Dict[str, Dict[str, str]], str]:
        """
        pyppasscrypt.cryptohandler.ISymmetricCryptoHandler.decrypt
        ----------------------------------------------------------

        Decrypt the given encrypted data using the provided password.

        :param encrypted_data: The data to decrypt, as bytes.
        :param password: The password to use for decryption.
        :return: The decrypted data as a dictionary or string.
        :raises ValueError: If decryption fails or if the password is empty.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class FernetCryptoHandler(ISymmetricCryptoHandler):
    """
    pypasscrypt.cryptohandler.FernetCryptoHandler
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
        pypasscrypt.cryptohandler.FernetCryptoHandler._get_cipher
        ---------------------------------------------------------

        Generate a cipher object using the input string as the key.

        :param input_string: The input string to generate the key.
        :return: A Fernet cipher object.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not input_string:
            raise ValueError("The input string must not be empty.")

        hash_digest: bytes = hashlib.sha256(input_string.encode()).digest()
        base64_key: bytes = base64.urlsafe_b64encode(hash_digest[:32])
        return Fernet(base64_key)

    @staticmethod
    def encrypt(*, data: Union[Dict[str, Dict[str, str]], str], password: str) -> bytes:
        """
        pypasscrypt.cryptohandler.FernetCryptoHandler.encrypt
        ------------------------------------------------------

        Encrypt the given data using the provided password.

        :param data: The data to encrypt, as a dictionary or string.
        :param password: The password to use for encryption.
        :return: Encrypted data as bytes.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not password:
            raise ValueError("The password must not be empty.")

        if isinstance(data, dict):
            data = json.dumps(data)

        cipher: Fernet = FernetCryptoHandler._get_cipher(input_string=password)
        encrypted_data: bytes = cipher.encrypt(data.encode())
        return encrypted_data

    @staticmethod
    def decrypt(*, encrypted_data: bytes, password: str) -> Union[Dict[str, Dict[str, str]], str]:
        """
        pypasscrypt.cryptohandler.FernetCryptoHandler.decrypt
        ------------------------------------------------------

        Decrypt the given encrypted data using the provided password.

        :param encrypted_data: The data to decrypt, as bytes.
        :param password: The password to use for decryption.
        :return: The decrypted data as a dictionary or string.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not password:
            raise ValueError("The password must not be empty.")

        cipher: Fernet = FernetCryptoHandler._get_cipher(input_string=password)
        try:
            decrypted_data: bytes = cipher.decrypt(encrypted_data)
        except Exception as e:
            raise ValueError(
                "Decryption failed. Check the password and data.") from e

        try:
            data: Dict[str, Dict[str, str]] = json.loads(
                decrypted_data.decode())
        except json.JSONDecodeError:
            return decrypted_data.decode()

        return data


class AESCryptoHandler(ISymmetricCryptoHandler):
    """
    pypasscrypt.cryptohandler.AESCryptoHandler
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
        pypasscrypt.cryptohandler.AESCryptoHandler._get_cipher
        -----------------------------------------------------

        Generate a cipher object using the input string as the key.

        :param input_string: The input string to generate the key.
        :return: A tuple containing the cipher object and IV.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not input_string:
            raise ValueError("The input string must not be empty.")

        key: bytes = hashlib.sha256(input_string.encode()).digest()
        iv: bytes = os.urandom(16)
        return Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend()), iv

    @staticmethod
    def encrypt(*, data: Union[Dict[str, Dict[str, str]], str], password: str) -> bytes:
        """
        pypasscrypt.cryptohandler.AESCryptoHandler.encrypt
        ---------------------------------------------------

        Encrypt the given data using the provided password.

        :param data: The data to encrypt, as a dictionary or string.
        :param password: The password to use for encryption.
        :return: Encrypted data as bytes.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not password:
            raise ValueError("The password must not be empty.")

        if isinstance(data, dict):
            data = json.dumps(data)
        cipher, iv = AESCryptoHandler._get_cipher(input_string=password)
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(
            data.encode()) + encryptor.finalize()
        return iv + encrypted_data

    @staticmethod
    def decrypt(*, encrypted_data: bytes, password: str) -> Union[Dict[str, Dict[str, str]], str]:
        """
        pypasscrypt.cryptohandler.AESCryptoHandler.decrypt
        ---------------------------------------------------

        Decrypt the given encrypted data using the provided password.

        :param encrypted_data: The data to decrypt, as bytes.
        :param password: The password to use for decryption.
        :return: The decrypted data as a dictionary or string.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not password:
            raise ValueError("The password must not be empty.")

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
            raise ValueError(
                "Decryption failed. Check the password and data.") from e

        try:
            data: Dict[str, Dict[str, str]] = json.loads(
                decrypted_data.decode())
        except json.JSONDecodeError:
            return decrypted_data.decode()
        return data


class PBKDF2CryptoHandler(ISymmetricCryptoHandler):
    """
    pypasscrypt.cryptohandler.PBKDF2CryptoHandler
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
        pypasscrypt.cryptohandler.PBKDF2CryptoHandler._get_cipher
        --------------------------------------------------------

        Generate a cipher object using the input string as the key.

        :param input_string: The input string to generate the key.
        :return: A tuple containing the cipher object and salt.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not input_string:
            raise ValueError("The input string must not be empty.")

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
    def encrypt(*, data: Union[Dict[str, Dict[str, str]], str], password: str) -> bytes:
        """
        pypasscrypt.cryptohandler.PBKDF2CryptoHandler.encrypt
        ------------------------------------------------------

        Encrypt the given data using the provided password.

        :param data: The data to encrypt, as a dictionary or string.
        :param password: The password to use for encryption.
        :return: Encrypted data as bytes.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not password:
            raise ValueError("The password must not be empty.")

        if isinstance(data, dict):
            data = json.dumps(data)
        cipher_data: Tuple[Cipher[CFB], bytes] = PBKDF2CryptoHandler._get_cipher(
            input_string=password)
        cipher: Cipher[CFB] = cipher_data[0]
        salt: bytes = cipher_data[1]
        encryptor: CipherContext = cipher.encryptor()
        encrypted_data: bytes = encryptor.update(
            data.encode()) + encryptor.finalize()
        return salt + encrypted_data

    @staticmethod
    def decrypt(*, encrypted_data: bytes, password: str) -> Union[Dict[str, Dict[str, str]], str]:
        """
        pypasscrypt.cryptohandler.PBKDF2CryptoHandler.decrypt
        ------------------------------------------------------

        Decrypt the given encrypted data using the provided password.

        :param encrypted_data: The data to decrypt, as bytes.
        :param password: The password to use for decryption.
        :return: The decrypted data as a dictionary or string.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not password:
            raise ValueError("The password must not be empty.")

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
            raise ValueError(
                "Decryption failed. Check the password and data.") from e

        try:
            data: Dict[str, Dict[str, str]] = json.loads(
                decrypted_data.decode())
        except json.JSONDecodeError:
            return decrypted_data.decode()
        return data


class ChaCha20CryptoHandler(ISymmetricCryptoHandler):
    """
    pypasscrypt.cryptohandler.ChaCha20CryptoHandler
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
        pypasscrypt.cryptohandler.ChaCha20CryptoHandler._get_cipher
        ----------------------------------------------------------

        Generate a cipher object using the input string as the key.

        :param input_string: The input string to generate the key.
        :return: A tuple containing the cipher object and nonce.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not input_string:
            raise ValueError("The input string must not be empty.")

        key: bytes = hashlib.sha256(input_string.encode()).digest()
        nonce: bytes = os.urandom(16)
        return Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend()), nonce

    @staticmethod
    def encrypt(*, data: Union[Dict[str, Dict[str, str]], str], password: str) -> bytes:
        """
        pypasscrypt.cryptohandler.ChaCha20CryptoHandler.encrypt
        --------------------------------------------------------

        Encrypt the given data using the provided password.

        :param data: The data to encrypt, as a dictionary or string.
        :param password: The password to use for encryption.
        :return: Encrypted data as bytes.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not password:
            raise ValueError("The password must not be empty.")

        if isinstance(data, dict):
            data = json.dumps(data)
        cipher_data: Tuple[Cipher[None], bytes] = ChaCha20CryptoHandler._get_cipher(
            input_string=password)
        cipher: Cipher[None] = cipher_data[0]
        nonce: bytes = cipher_data[1]
        encryptor: CipherContext = cipher.encryptor()
        encrypted_data: bytes = encryptor.update(data.encode())
        return nonce + encrypted_data

    @staticmethod
    def decrypt(*, encrypted_data: bytes, password: str) -> Union[Dict[str, Dict[str, str]], str]:
        """
        pypasscrypt.cryptohandler.ChaCha20CryptoHandler.decrypt
        --------------------------------------------------------

        Decrypt the given encrypted data using the provided password.

        :param encrypted_data: The data to decrypt, as bytes.
        :param password: The password to use for decryption.
        :return: The decrypted data as a dictionary or string.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not password:
            raise ValueError("The password must not be empty.")

        try:
            nonce: bytes = encrypted_data[:16]
            ciphertext: bytes = encrypted_data[16:]
            key: bytes = hashlib.sha256(password.encode()).digest()
            cipher: Cipher = Cipher(algorithms.ChaCha20(key, nonce),
                                    mode=None, backend=default_backend())
            decryptor: CipherContext = cipher.decryptor()
            decrypted_data: bytes = decryptor.update(ciphertext)
        except Exception as e:
            raise ValueError(
                "Decryption failed. Check the password and data.") from e

        try:
            data: Dict[str, Dict[str, str]] = json.loads(
                decrypted_data.decode())
        except json.JSONDecodeError:
            return decrypted_data.decode()
        return data


class IAsymmetricCryptoHandler(ABC):
    """
    pypasscrypt.cryptohandler.IAsymmetricCryptoHandler
    --------------------------------------------------

    Interface for handling encryption/decryption for connection between two parties.

    Supported methods:
    ------------------
    - `generate_keys()`: Generate a new private-public key pair.
    - `encrypt()`: Encrypt data using the provided public key.
    - `decrypt()`: Decrypt encrypted data using the provided private key.

    Supported classes:
    ------------------
    - `RSACryptoHandler`: RSA asymmetric encryption.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    @abstractmethod
    def generate_keys() -> Tuple[bytes, bytes]:
        """
        pypasscrypt.cryptohandler.IAsymmetricCryptoHandler.generate_keys
        -----------------------------------------------------------------

        Generate a new private-public key pair.

        :return: A tuple containing the private key and public key in PEM format.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def encrypt(*, json_data: Dict[str, Dict[str, str]], public_key_pem: bytes) -> bytes:
        """
        pypasscrypt.cryptohandler.IAsymmetricCryptoHandler.encrypt
        ----------------------------------------------------------

        Encrypt the given data using the provided public key.

        :param json_data: The data to encrypt, as a dictionary.
        :param public_key_pem: The public key in PEM format.
        :return: Encrypted data as bytes.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def decrypt(*, encrypted_data: bytes, private_key_pem: bytes) -> Dict[str, Dict[str, str]]:
        """
        pypasscrypt.cryptohandler.IAsymmetricCryptoHandler.decrypt
        ----------------------------------------------------------

        Decrypt the given encrypted data using the provided private key.

        :param encrypted_data: The data to decrypt, as bytes.
        :param private_key_pem: The private key in PEM format.
        :return: The decrypted data as a dictionary.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class RSACryptoHandler(IAsymmetricCryptoHandler):
    """
    pypasscrypt.cryptohandler.RSACryptoHandler
    ------------------------------------------

    A class to handle encryption/decryption of data using RSA asymmetric encryption.

    Supported methods:
    ------------------
    - `generate_keys()`: Generate a new private-public key pair.
    - `encrypt()`: Encrypt data using the provided public key.
    - `decrypt()`: Decrypt encrypted data using the provided private key.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def generate_keys() -> Tuple[bytes, bytes]:
        """
        pypasscrypt.cryptohandler.RSACryptoHandler.generate_keys
        --------------------------------------------------------

        Generate a new RSA private-public key pair.

        :return: A tuple containing the private key and public key in PEM format.

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
    def encrypt(*, json_data: Dict[str, Dict[str, str]], public_key_pem: bytes) -> bytes:
        """
        pypasscrypt.cryptohandler.RSACryptoHandler.encrypt
        --------------------------------------------------

        Encrypt the given data using the provided RSA public key.

        :param json_data: The data to encrypt, as a dictionary.
        :param public_key_pem: The RSA public key in PEM format.
        :return: Encrypted data as bytes.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        json_str = json.dumps(json_data)

        public_key: PublicKeyTypes = serialization.load_pem_public_key(
            public_key_pem, backend=default_backend())
        if not isinstance(public_key, RSAPublicKey):
            raise ValueError("Invalid RSA public key.")

        encrypted_data = public_key.encrypt(
            json_str.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_data

    @staticmethod
    def decrypt(*, encrypted_data: bytes, private_key_pem: bytes) -> Dict[str, Dict[str, str]]:
        """
        pypasscrypt.cryptohandler.RSACryptoHandler.decrypt
        --------------------------------------------------

        Decrypt the given encrypted data using the provided RSA private key.

        :param encrypted_data: The data to decrypt, as bytes.
        :param private_key_pem: The RSA private key in PEM format.
        :return: The decrypted data as a dictionary.
        :raises ValueError: If decryption fails or if the password is empty.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        private_key: PrivateKeyTypes = serialization.load_pem_private_key(
            private_key_pem, password=None, backend=default_backend())
        if not isinstance(private_key, RSAPrivateKey):
            raise ValueError("Invalid RSA private key.")

        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        try:
            json_data: Dict[str, Dict[str, str]] = json.loads(
                decrypted_data.decode())
        except json.JSONDecodeError as e:
            raise ValueError("Failed to decode JSON data.") from e

        return json_data


class IHashing(ABC):
    """
    pypasscrypt.cryptohandler.IHashing
    ----------------------------------

    Interface for handling hashing of data.

    Supported methods:
    ------------------
    - `generate_hash()`: Compute the SHA-256 hash of the given data.
    - `verify_hash()`: Verify the SHA-256 hash of the given data.

    Supported classes:
    ------------------
    - `Hashing`: A class to handle hashing of data using various hashing methods.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    @abstractmethod
    def generate_hash(*, raw_str: str) -> bytes:
        """
        pypasscrypt.cryptohandler.IHashing.generate_hash
        ------------------------------------------------

        Compute the SHA-256 hash of the given data.

        :param raw_str: The data to hash, as a string.
        :return: The SHA-256 hash of the data.
        :raises ValueError: If the data is empty.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def verify_hash(*, raw_str: str, hash_bytes: bytes) -> bool:
        """
        pypasscrypt.cryptohandler.IHashing.verify_hash
        -----------------------------------------------

        Verify the SHA-256 hash of the given data.

        :param raw_str: The data to verify, as a string.
        :param hash_bytes: The hash to verify against.
        :return: True if the hash matches, False otherwise.
        :raises ValueError: If the data is empty.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class Hashing(IHashing):
    """
    pypasscrypt.cryptohandler.Hashing
    ---------------------------------

    A class to handle hashing of data using various hashing methods.

    Supported methods:
    ------------------
    - `generate_hash()`: Compute the SHA-256 hash of the given data.
    - `verify_hash()`: Verify the SHA-256 hash of the given data.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def generate_hash(*, raw_str: str) -> bytes:
        """
        pypasscrypt.cryptohandler.Hashing.generate_hash
        -----------------------------------------------

        Compute the SHA-256 hash of the given data.

        :param raw_str: The data to hash, as a string.
        :return: The SHA-256 hash of the data.
        :raises ValueError: If the data is empty.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not raw_str:
            raise ValueError("The data to hash must not be empty.")

        return bytes.fromhex(hashlib.sha256(raw_str.encode()).hexdigest())

    @staticmethod
    def verify_hash(*, raw_str: str, hash_bytes: bytes) -> bool:
        """
        pypasscrypt.cryptohandler.Hashing.verify_hash
        ----------------------------------------------

        Verify the SHA-256 hash of the given data.

        :param raw_str: The data to verify, as a string.
        :param hash_bytes: The hash to verify against.
        :return: True if the hash matches, False otherwise.
        :raises ValueError: If the data is empty.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not raw_str:
            raise ValueError("The data to verify must not be empty.")

        if not hash_bytes:
            raise ValueError("The hash to verify against must not be empty.")

        return Hashing.generate_hash(raw_str=raw_str) == hash_bytes


SymmetricEncryptionTypes = Literal["Fernet", "AES", "PBKDF2", "ChaCha20"]
"""
pypasscrypt.cryptohandler.SymmetricEncryptionTypes
--------------------------------------------------

Supported symmetric encryption types.

values:
------
- `Fernet`: Fernet symmetric encryption.
- `AES`: AES symmetric encryption.
- `PBKDF2`: Key derivation using PBKDF2 and AES encryption.
- `ChaCha20`: ChaCha20 symmetric encryption.

Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
"""


AsymmetricEncryptionTypes = Literal["RSA"]
"""
pypasscrypt.cryptohandler.AsymmetricEncryptionTypes
--------------------------------------------------

Supported asymmetric encryption types.

Values:
------
- `RSA`: RSA asymmetric encryption.

Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
"""


class SymmetricCryptoHandler:
    """
    pypasscrypt.cryptohandler.SymmetricCryptoHandler
    ------------------------------------------------

    A class to handle encryption/decryption of data using various symmetric and asymmetric encryption methods.

    Supported types:
    ----------------
    - `Fernet`: Fernet symmetric encryption.
    - `AES`: AES symmetric encryption.
    - `PBKDF2`: Key derivation using PBKDF2 and AES encryption.
    - `ChaCha20`: ChaCha20 symmetric encryption.

    Methods:
    --------
    - `encrypt()`: Encrypt data using the provided password and encryption method.
    - `decrypt()`: Decrypt encrypted data using the provided password and encryption method.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def encrypt(
            *,
            data: Union[Dict[str, Dict[str, str]], str],
            password: str,
            method: SymmetricEncryptionTypes
    ) -> bytes:
        """
        pypasscrypt.cryptohandler.SymmetricCryptoHandler.encrypt
        --------------------------------------------------------

        Encrypt the given data using the provided password and encryption method.

        :param data: The data to encrypt, as a dictionary or string.
        :param password: The password to use for encryption.
        :param method: The encryption method to use.
        :return: Encrypted data as bytes.
        :raises ValueError: If the password is empty or the encryption method is not supported.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if method == "Fernet":
            return FernetCryptoHandler.encrypt(
                data=data,
                password=password
            )
        elif method == "AES":
            return AESCryptoHandler.encrypt(
                data=data,
                password=password
            )
        elif method == "PBKDF2":
            return PBKDF2CryptoHandler.encrypt(
                data=data,
                password=password
            )
        elif method == "ChaCha20":
            return ChaCha20CryptoHandler.encrypt(
                data=data,
                password=password
            )
        else:
            raise ValueError("Unsupported symmetric encryption method.")

    @staticmethod
    def decrypt(
            *,
            encrypted_data: bytes,
            password: str,
            method: SymmetricEncryptionTypes
    ) -> Union[Dict[str, Dict[str, str]], str]:
        """
        pypasscrypt.cryptohandler.SymmetricCryptoHandler.decrypt
        --------------------------------------------------------

        Decrypt the given encrypted data using the provided password and encryption method.

        :param encrypted_data: The data to decrypt, as bytes.
        :param password: The password to use for decryption.
        :param method: The encryption method to use.
        :return: The decrypted data as a dictionary.
        :raises ValueError: If decryption fails, the password is empty, or the encryption method is not supported.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if method == "Fernet":
            return FernetCryptoHandler.decrypt(
                encrypted_data=encrypted_data,
                password=password
            )
        elif method == "AES":
            return AESCryptoHandler.decrypt(
                encrypted_data=encrypted_data,
                password=password
            )
        elif method == "PBKDF2":
            return PBKDF2CryptoHandler.decrypt(
                encrypted_data=encrypted_data,
                password=password
            )
        elif method == "ChaCha20":
            return ChaCha20CryptoHandler.decrypt(
                encrypted_data=encrypted_data,
                password=password
            )
        else:
            raise ValueError("Unsupported symmetric encryption method.")


class AsymmetricCryptoHandler:
    """
    pypasscrypt.cryptohandler.AsymmetricCryptoHandler
    -------------------------------------------------

    A class to handle encryption/decryption of data using various asymmetric encryption methods.

    Supported types:
    ---------------
    - `RSA`: RSA asymmetric encryption.

    Methods:
    -------
    - `generate_keys()`: Generate a new private-public key pair.
    - `encrypt()`: Encrypt data using the provided public key and encryption method.
    - `decrypt()`: Decrypt encrypted data using the provided private key and encryption method.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def generate_keys(method: AsymmetricEncryptionTypes) -> Tuple[bytes, bytes]:
        """
        pypasscrypt.cryptohandler.AsymmetricCryptoHandler.generate_keys
        -----------------------------------------------------------------

        Generate a new private-public key pair using the provided encryption method.

        :param method: The encryption method to use.
        :return: A tuple containing the private key and public key in PEM format.
        :raises ValueError: If the encryption method is not supported.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if method == "RSA":
            return RSACryptoHandler.generate_keys()
        else:
            raise ValueError("Unsupported asymmetric encryption method.")

    @staticmethod
    def encrypt(*, json_data: Dict[str, Dict[str, str]], public_key_pem: bytes,
                method: AsymmetricEncryptionTypes) -> bytes:
        """
        pypasscrypt.cryptohandler.AsymmetricCryptoHandler.encrypt
        --------------------------------------------------------
        
        Encrypt the given data using the provided public key and encryption method.

        :param json_data: The data to encrypt, as a dictionary.
        :param public_key_pem: The public key in PEM format.
        :param method: The encryption method to use.
        :return: Encrypted data as bytes.
        :raises ValueError: If the encryption method is not supported.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if method == "RSA":
            return RSACryptoHandler.encrypt(
                json_data=json_data,
                public_key_pem=public_key_pem
            )
        else:
            raise ValueError("Unsupported asymmetric encryption method.")

    @staticmethod
    def decrypt(
            *,
            encrypted_data: bytes,
            private_key_pem: bytes,
            method: AsymmetricEncryptionTypes
    ) -> Dict[str, Dict[str, str]]:
        """
        pypasscrypt.cryptohandler.AsymmetricCryptoHandler.decrypt
        --------------------------------------------------------

        Decrypt the given encrypted data using the provided private key and encryption method.

        :param encrypted_data: The data to decrypt, as bytes.
        :param private_key_pem: The private key in PEM format.
        :param method: The encryption method to use.
        :return: The decrypted data as a dictionary.
        :raises ValueError: If decryption fails or the encryption method is not supported.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if method == "RSA":
            return RSACryptoHandler.decrypt(
                encrypted_data=encrypted_data,
                private_key_pem=private_key_pem
            )
        else:
            raise ValueError("Unsupported asymmetric encryption method.")
