"""
# pypasscrypt.storagehandler
-------------------

The module to manage password storage.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Types:
----------
- `PasswordBucket`: The dataclass to store passwords.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Exceptions:
----------
- `InvalidPasswordBucketError`: The exception raised when the password bucket is invalid.
- `InvalidEPCFileError`: The exception raised when the EPC file is invalid.
- `InvalidEPTFileError`: The exception raised when the EPT file is invalid.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Classes:
--------
- `EPC``: The Encrypted Password Container (EPC) for operations on epc files.
- `EPT``: The Encrypted Password Transfer (EPT) for operations on ept files.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
    'InvalidPasswordBucketError',
    'InvalidEPCFileError',
    'InvalidEPTFileError',
    'PasswordBucket',
    'EPC',
    'EPT',
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    '__copyright__',
    '__status__'
]

from binascii import hexlify, unhexlify
from dataclasses import dataclass, field
from itertools import count
import json
import os
from datetime import datetime
from struct import (
    pack,
    unpack
)
from types import TracebackType
from typing import (
    Dict,
    Optional,
    Tuple,
    List,
    get_args
)
from pypasscrypt.cryptohandler import (
    SymmetricCryptoHandler,
    SymmetricEncryptionTypes,
    InvalidSymmetricEncryptionTypeError,
    HashHandler,
    HashTypes,
    InvalidHashTypeError
)
from logging import Logger


class InvalidPasswordBucketError(Exception):
    """
    # pypasscrypt.storagehandler.InvalidPasswordBucketError
    ------------------------------------------

    The exception raised when the password bucket is invalid.

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, message: str) -> None:
        """
        # pypasscrypt.storagehandler.InvalidPasswordBucketError.__init__
        ---------------------------------------------------

        Initialize the InvalidPasswordBucketError object.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The error message.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the message is not a string.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(message, str):
            raise TypeError("Message must be a string.")

        super().__init__(message)


class InvalidEPCFileError(Exception):
    """
    # pypasscrypt.storagehandler.InvalidEPCFileError
    ------------------------------------------

    The exception raised when the EPC file is invalid.

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, message: str) -> None:
        """
        # pypasscrypt.storagehandler.InvalidEPCFileError.__init__
        ---------------------------------------------------

        Initialize the InvalidEPCFileError object.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The error message.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the message is not a string.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(message, str):
            raise TypeError("Message must be a string.")

        super().__init__(message)


class InvalidEPTFileError(Exception):
    """
    # pypasscrypt.storagehandler.InvalidEPTFileError
    ------------------------------------------

    The exception raised when the EPT file is invalid.

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, message: str) -> None:
        """
        # pypasscrypt.storagehandler.InvalidEPTFileError.__init__
        ---------------------------------------------------

        Initialize the InvalidEPTFileError object.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The error message.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the message is not a string.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(message, str):
            raise TypeError("Message must be a string.")

        super().__init__(message)


@dataclass
class PasswordBucket:
    """
    # pypasscrypt.storagehandler.PasswordBucket
    -----------------------------------

    The PasswordBucket class to store passwords.

    ~~~~~~~~~~~~~~~

    Methods:
    --------
    - `get_all_sites()`: Get all the sites stored in the storage.
    - `get_all_usernames()`: Get all the usernames stored in the storage.
    - `get_listings()`: Get all the sites and usernames stored in the storage.
    - `is_site_exists()`: Check if a site exists in the storage.
    - `get_usernames_by_sites()`: Get the usernames for a specific site.
    - `is_username_exists()`: Check if a username exists for a site.
    - `add_password()`: Add a password to the storage.
    - `get_password()`: Get the password for a site and username.
    - `edit_password()`: Edit a password in the storage.
    - `remove_password()`: Remove a password from the storage.
    - `__str__()`: Get the string representation of the PasswordBucket object.
    - `from_string()`: Create a PasswordBucket object from a string.

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    data: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        # pypasscrypt.storagehandler.PasswordBucket.__post_init__
        ------------------------------------------------

        Post-initialize the PasswordBucket object.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `InvalidPasswordBucketError` if the password bucket is invalid.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(self.data, dict):
            raise InvalidPasswordBucketError(
                message="Invalid dictionary for password bucket.") from TypeError("Data must be a dictionary.")

        for site in self.data:
            if not isinstance(site, str):
                raise InvalidPasswordBucketError(
                    message="Invalid dictionary for password bucket.") from TypeError(f"Invalid site name: {site}")

            for username, password in self.data[site].items():
                if not isinstance(username, str):
                    raise InvalidPasswordBucketError(message="Invalid dictionary for password bucket.") from TypeError(
                        f"Invalid username: {username}")

                if not isinstance(password, str):
                    raise InvalidPasswordBucketError(message="Invalid dictionary for password bucket.") from TypeError(
                        f"Invalid password: {password}")

    def get_all_sites(self) -> List[str]:
        """
        # pypasscrypt.storagehandler.PasswordBucket.get_all_sites
        --------------------------------

        Get all the sites stored in the storage.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        The list of sites in the storage.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        return list(self.data.keys())
    
    def get_all_usernames(self) -> List[str]:
        """
        # pypasscrypt.storagehandler.PasswordBucket.get_all_usernames
        --------------------------------

        Get all the usernames stored in the storage.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        The list of usernames in the storage.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        return list(set([username for site in self.data for username in self.data[site]]))

    def get_listings(self) -> List[Tuple[str, str]]:
        """
        # pypasscrypt.storagehandler.PasswordBucket.get_listings
        --------------------------------

        Get all the sites and usernames stored in the storage.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the site name is not a string.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        The list of sites and usernames in current commit.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        return [(site, username) for site in self.data for username in self.data[site]]

    def is_site_exists(
            self,
            *,
            site: str
    ) -> bool:
        """
        # pypasscrypt.storagehandler.PasswordBucket.is_site_exists
        --------------------------------

        Check if a site exists in the storage.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to check.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `InvalidPasswordBucketError` if the site is not a string.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        If the site exists in the storage.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise InvalidPasswordBucketError(
                message="Site name must be a string.") from TypeError(site)

        return site in self.data.keys()

    def get_usernames_by_site(
            self,
            *,
            site: str
    ) -> List[str]:
        """
        # pypasscrypt.storagehandler.PasswordBucket.get_usernames
        --------------------------------

        Get the usernames for a specific site.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to get data for.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `InvalidPasswordBucketError` if the site is invalid.

        ~~~~~~~~~~~~~~~

        Return:
        The list of usernames for the site.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise InvalidPasswordBucketError(
                message="Site name must be a string.") from TypeError(site)

        if site not in self.data:
            raise InvalidPasswordBucketError(
                message=f"Site not found: {site}") from ValueError(site)

        return list(self.data[site].keys())

    def is_username_exists(
            self,
            *,
            site: str,
            username: str
    ) -> bool:
        """
        # pypasscrypt.storagehandler.PasswordBucket.is_username_exists
        --------------------------------

        Check if a username exists for a site.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to check.
        - `username`: The username to check.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `InvalidPasswordBucketError` if parameters are invalid.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        If the username exists for the site.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise TypeError("Site name must be a string.")

        if not isinstance(username, str):
            raise TypeError("Username name must be a string.")
        
        if not self.is_site_exists(site=site):
            return False

        return username in self.data[site]

    def add_password(
            self,
            *,
            site: str,
            username: str,
            password: str
    ) -> None:
        """
        # pypasscrypt.storagehandler.PasswordBucket.add_password
        --------------------------------

        Add a password to the storage.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to add password for.
        - `username`: The username to add password for.
        - `password`: The password to add.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `InvalidPasswordBucketError` if parameters are invalid.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise InvalidPasswordBucketError(
                message="Site name must be a string.") from TypeError(site)

        if not isinstance(username, str):
            raise InvalidPasswordBucketError(
                message="Username name must be a string.") from TypeError(username)

        if not isinstance(password, str):
            raise InvalidPasswordBucketError(
                message="Password name must be a string.") from TypeError(password)

        if site not in self.data:
            self.data[site] = {}

        if username in self.data[site]:
            raise InvalidPasswordBucketError(
                message=f"Username already exists: {username}") from ValueError(username)

        self.data[site][username] = password

    def get_password(
            self,
            *,
            site: str,
            username: str
    ) -> str:
        """
        # pypasscrypt.storagehandler.PasswordBucket.get_password
        --------------------------------

        Get the password for a site and username.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to get password for.
        - `username`: The username to get password for.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `InvalidPasswordBucketError` if parameters are invalid.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        The password for the site and username.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise InvalidPasswordBucketError(
                message="Site name must be a string.") from TypeError(site)

        if not isinstance(username, str):
            raise InvalidPasswordBucketError(
                message="Username name must be a string.") from TypeError(username)

        if site not in self.data:
            raise InvalidPasswordBucketError(
                message=f"Site not found: {site}") from ValueError(site)

        if username not in self.data[site]:
            raise InvalidPasswordBucketError(
                message=f"Username not found: {username}") from ValueError(username)

        return self.data[site][username]

    def edit_password(
            self,
            *,
            site: str,
            username: str,
            password: str
    ) -> None:
        """
        # pypasscrypt.storagehandler.PasswordBucket.edit_password
        --------------------------------

        Edit a password in the storage.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to edit password for.
        - `username`: The username to edit password for.
        - `password`: The password to edit.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `InvalidPasswordBucketError` if parameters are invalid.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise InvalidPasswordBucketError(
                message="Site name must be a string.") from TypeError(site)

        if not isinstance(username, str):
            raise InvalidPasswordBucketError(
                message="Username name must be a string.") from TypeError(username)

        if not isinstance(password, str):
            raise InvalidPasswordBucketError(
                message="Password name must be a string.") from TypeError(password)

        if site not in self.data:
            raise InvalidPasswordBucketError(
                message=f"Site not found: {site}") from ValueError(site)

        if username not in self.data[site]:
            raise InvalidPasswordBucketError(
                message=f"Username not found: {username}") from ValueError(username)

        self.data[site][username] = password

    def remove_password(
            self,
            *,
            site: str,
            username: str
    ) -> None:
        """
        # pypasscrypt.storagehandler.PasswordBucket.remove_password
        --------------------------------

        Remove a password from the storage.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to remove password from.
        - `username`: The username to remove password from.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `InvalidPasswordBucketError` if parameters are invalid.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise InvalidPasswordBucketError(
                message="Site name must be a string.") from TypeError(site)

        if not isinstance(username, str):
            raise InvalidPasswordBucketError(
                message="Username name must be a string.") from TypeError(username)

        if site not in self.data:
            raise InvalidPasswordBucketError(
                message=f"Site not found: {site}") from ValueError(site)

        if username not in self.data[site]:
            raise InvalidPasswordBucketError(
                message=f"Username not found: {username}") from ValueError(username)

        del self.data[site][username]

        if len(self.data[site]) == 0:
            del self.data[site]

    def __str__(self) -> str:
        """
        # pypasscrypt.storagehandler.PasswordBucket.__str__
        --------------------------------

        Get the string representation of the PasswordBucket object.

        ~~~~~~~~~~~~~~~

        Return:
        The string representation of the PasswordBucket object.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        return json.dumps(self.data, indent=4)

    @staticmethod
    def from_string(data: str) -> 'PasswordBucket':
        """
        # pypasscrypt.storagehandler.PasswordBucket.from_string
        --------------------------------

        Create a PasswordBucket object from a string.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The string data.

        ~~~~~~~~~~~~~~~

        Return:
        The PasswordBucket object.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        return PasswordBucket(data=json.loads(data))


class EPC:
    """
    # pypasscrypt.storagehandler.EPC
    ------------------------

    The Encrypted Password Container (EPC) class to manage password storage.

    ~~~~~~~~~~~~~~~

    Methods:
    --------
    - `verify()`: Verify the EPC file against provided details.
    - `load()`: Load the current commit data from the EPC object.
    - `save()`: Save the new commit to the EPC object.
    - `load_commits()`: Load all the commits from the EPC object.
    - `load_commit_data()`: Get the commit message and data for a specific commit hash.
    - `revert_to_commit()`: Revert the storage to a specific commit hash.
    - `change_secret()`: Change the secret to encrypt/decrypt the passwords.
    - `change_encryption_type()`: Change the encryption type.
    - `get_all_sites()`: Get all the sites stored in the storage.
    - `get_listings()`: Get all the sites and usernames stored in the storage.
    - `is_site_exists()`: Check if a site exists in the storage.
    - `get_usernames()`: Get the usernames for a specific site.
    - `is_username_exists()`: Check if a username exists for a site.
    - `add_password()`: Add a password to the storage.
    - `get_password()`: Get the password for a site and username.
    - `edit_password()`: Edit a password in the storage.
    - `remove_password()`: Remove a password from the storage.
    - `import_data()`: Import new data.
    - `export_data()`: Export data.
    - `create()`: Create a new EPC file.

    ~~~~~~~~~~~~~~~

    Attributes:
    -----------
    - `FILE_VERSION``: The file version of the EPC object.

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    FILE_VERSION: str = "EPCv1.0"
    """
    # pypasscrypt.storagehandler.EPC.FILE_VERSION
    -----------------------------------

    The file version of the EPC file.

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    FILE_EXTENSION: str = "epc"
    """
    # pypasscrypt.storagehandler.EPC.FILE_EXTENSION
    -----------------------------------

    The file extension of the EPC file.

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            hash_type: HashTypes,
            logger: Logger
    ) -> None:
        """
        # pypasscrypt.storagehandler.EPC.__init__
        --------------------------------

        Initialize the EPC object.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `file_path`: The file path to manage password storage.
        - `secret`: The password to encrypt/decrypt the passwords.
        - `symmetric_encryption_type`: The encryption method to use.
        - `hash_type`: The hash type to use.
        - `logger_type`: The logger type.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the parameters are invalid.
        - `ValueError` if the file extension is invalid.
        - `InvalidSymmetricEncryptionTypeError` if the symmetric encryption type is invalid.
        - `InvalidHashTypeError` if the hash type is invalid.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(file_path, str):
            raise TypeError("File path must be a string.")

        if not file_path.endswith(self.FILE_EXTENSION):
            raise ValueError(
                f"Only {self.FILE_EXTENSION} files are supported.")

        if not isinstance(secret, str):
            raise TypeError("Secret must be a string.")

        if symmetric_encryption_type not in get_args(SymmetricEncryptionTypes):
            raise InvalidSymmetricEncryptionTypeError(
                message=f"Invalid symmetric encryption type: {symmetric_encryption_type}")

        if hash_type not in get_args(HashTypes):
            raise InvalidHashTypeError(
                message=f"Invalid hash type: {hash_type}")

        if not isinstance(logger, Logger):
            raise TypeError("Logger must be a Logger.")

        self.file_path: str = file_path
        self.secret: str = secret
        self.symmetric_encryption_type: SymmetricEncryptionTypes = symmetric_encryption_type
        self.hash_type: HashTypes = hash_type
        self.logger: Logger = logger
        self.hash_length: int = 32
        self.current_commit_hash: str = ""

        # Verify the EPC object
        self.verify()

    def __enter__(self) -> 'EPC':
        """
        # pypasscrypt.storagehandler.EPC.__enter__
        ----------------------------------

        Enter the context manager.

        ~~~~~~~~~~~~~~~

        Return:
        The EPC object.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        return self

    def __exit__(self, exc_type: Exception, exc_value: Exception, exc_traceback: TracebackType) -> None:
        """
        # pypasscrypt.storagehandler.EPC.__exit__
        ---------------------------------

        Exit the context manager.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `exc_type`: The exception type.
        - `exc_value`: The exception value.
        - `exc_traceback`: The exception traceback.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `Exception` if an exception occurs.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if exc_type:
            self.logger.error(msg=str(exc_value))

        raise exc_value.with_traceback(exc_traceback) from exc_type

    def verify(self) -> None:
        """
        # pypasscrypt.storagehandler.EPC.verify
        -------------------------------

        Verify the EPC file against provided details.

        ~~~~~~~~~~~~~~~

        Raise:
        ------- 
        - `InvalidEPCFileError` if the file is invalid.
        - `FileNotFoundError` if the file is not found.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        try:
            with open(self.file_path, 'rb+') as file:
                file.seek(0)

                # Verify file version (32 bytes)
                if not HashHandler.verify_hash(
                        data=self.FILE_VERSION,
                        hash_data=hexlify(file.read(32)).decode(),
                        method="SHA256"
                ):
                    raise ValueError("Invalid file version")

                # Verify file hash (32 bytes)
                elif not HashHandler.verify_hash(
                        data=self.secret,
                        hash_data=hexlify(file.read(32)).decode(),
                        method="SHA256"
                ):
                    raise ValueError("Invalid password")

                # Verify encryption type (32 bytes)
                elif not HashHandler.verify_hash(
                        data=self.symmetric_encryption_type,
                        hash_data=hexlify(file.read(32)).decode(),
                        method="SHA256"
                ):
                    raise ValueError("Invalid encryption type")
                
                # Verify hash type (32 bytes)
                elif not HashHandler.verify_hash(
                        data=self.hash_type,
                        hash_data=hexlify(file.read(32)).decode(),
                        method="SHA256"
                ):
                    raise ValueError("Invalid hash type")
                
                # Read commit hash length (4 bytes)
                self.hash_length = unpack('I', file.read(4))[0]
                self.current_commit_hash = hexlify(file.read(self.hash_length)).decode()

        except ValueError as e:
            raise InvalidEPCFileError(message="Invalid file") from e

        self.logger.info(msg="Verified EPC file")

    def load(self, reason: str) -> PasswordBucket:
        """
        # pypasscrypt.storagehandler.EPC.load
        -----------------------------

        Load the current commit data from the EPC object.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `reason`: The reason for loading the data.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        The current commit data.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        # Verify the EPC object
        self.verify()

        # Get the data for the current commit hash
        data: Tuple[str, PasswordBucket] = self.load_commit_data(commit_hash=self.current_commit_hash)

        # Log the data load
        self.logger.info(msg=f"Loaded data for: {reason}")

        return data[1]

    def save(
            self,
            *,
            commit_data: PasswordBucket,
            commit_message: str
    ) -> None:
        """
        # pypasscrypt.storagehandler.EPC.save
        -----------------------------

        Save the new commit to the EPC object.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `commit_data`: The data to commit.
        - `commit_message`: The commit message.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.verify()

        temp_file_path: str = f"{self.file_path}.tmp"
        with open(self.file_path, 'rb+') as epc_file, open(temp_file_path, 'wb+') as tmp_file:
            # seek to start
            tmp_file.seek(0)

            # Write file version (32 bytes)
            hashed_file_version: bytes = unhexlify(HashHandler.generate_hash(
                data=EPC.FILE_VERSION,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_file_version)=:>25}  {hashed_file_version=}")
            tmp_file.write(hashed_file_version)

            # Write password hash (32 bytes)
            hashed_secret: bytes = unhexlify(HashHandler.generate_hash(
                data=self.secret,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_secret)=:>31}  {hashed_secret=}")
            tmp_file.write(hashed_secret)

            # Write encryption type hash (32 bytes)
            hashed_symmetric_encryption_type: bytes = unhexlify(HashHandler.generate_hash(
                data=self.symmetric_encryption_type,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_symmetric_encryption_type)=:>12}  {hashed_symmetric_encryption_type=}")
            tmp_file.write(hashed_symmetric_encryption_type)

            # Write hash type hash (32 bytes)
            hashed_hash_type: bytes = unhexlify(HashHandler.generate_hash(
                data=self.hash_type,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_hash_type)=:>28}  {hashed_hash_type=}")
            tmp_file.write(hashed_hash_type)

            # create a new commit hash
            new_commit_hash: bytes = unhexlify(HashHandler.generate_hash(
                data=datetime.now().isoformat(),
                method=self.hash_type
            ).encode())

            # write current commit hash length (4 bytes)
            packed_hash_length: bytes = pack('I', len(new_commit_hash))
            # print(f"{len(packed_hash_length)=:>26}  {packed_hash_length=}")
            tmp_file.write(packed_hash_length)

            # print("base structure size:                          ", tmp_file.tell(), end="\n\n")

            # encrypt the message
            encrypted_message: bytes = SymmetricCryptoHandler.encrypt(
                data=commit_message,
                password=self.secret,
                method=self.symmetric_encryption_type
            )

            # encrypt the data
            encrypted_data: bytes = SymmetricCryptoHandler.encrypt(
                data=str(commit_data),
                password=self.secret,
                method=self.symmetric_encryption_type
            )

            # Write the new commit
            # print(f"{len(new_commit_hash)=:>29}  {new_commit_hash=}")
            tmp_file.write(new_commit_hash)

            # Write the current commit
            # print(f"{len(new_commit_hash)=:>29}  {new_commit_hash=}")
            tmp_file.write(new_commit_hash)

            tmp_file.write(pack('I', len(encrypted_message)))
            # print(f"{len(encrypted_message)=:>27}  {encrypted_message=}")
            tmp_file.write(encrypted_message)

            tmp_file.write(pack('I', len(encrypted_data)))
            # print(f"{len(encrypted_data)=:>30}  {encrypted_data=}")
            tmp_file.write(encrypted_data)

            epc_file.seek(132 + self.hash_length)

            # Write the rest of the file
            while True:
                current_commit_hash: bytes = epc_file.read(self.hash_length)

                if not current_commit_hash:
                    break

                # print(f"{len(current_commit_hash)=:>25}  {current_commit_hash=}")
                
                commit_message_length: int = unpack('I', epc_file.read(4))[0]
                encrypted_commit_message = epc_file.read(commit_message_length)
                # print(f"{commit_message_length=:>28}  {encrypted_commit_message=}")


                commit_data_length: int = unpack('I', epc_file.read(4))[0]
                encrypted_commit_data = epc_file.read(commit_data_length)
                # print(f"{commit_data_length=:>31}  {encrypted_commit_data=}")

                tmp_file.write(current_commit_hash)
                tmp_file.write(pack('I', commit_message_length))
                tmp_file.write(encrypted_commit_message)
                tmp_file.write(pack('I', commit_data_length))
                tmp_file.write(encrypted_commit_data)

                

        # Log the commit save
        self.logger.info(msg=commit_message)
        self.logger.info(
            msg=f"Saved data to new commit - {hexlify(new_commit_hash).decode()}")

        # Replace the old file with the new file
        os.replace(temp_file_path, self.file_path)

    def load_commits(self) -> List[Tuple[str, str]]:
        """
        # pypasscrypt.storagehandler.EPC.load_commits
        ------------------------------------

        Load all the commits from the EPC object.

        ~~~~~~~~~~~~~~~

        Raise:
        ------- 
        - `InvalidEPCFileError` if the file is corrupt.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        The list of commits along with hash, message in the EPC object.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.verify()
        try:

            with open(self.file_path, 'rb+') as file:
                file.seek(132 + self.hash_length)  # Skip the first 5 hashes
                commits: List[Tuple[str, str]] = []

                while True:
                    # Read the current commit hash
                    current_commit_hash: bytes = file.read(self.hash_length)

                    # Check if the commit hash is valid
                    if not current_commit_hash:
                        break
                    # print(f"{len(current_commit_hash)=:>25}  {current_commit_hash=}")

                    # Read the commit message
                    commit_message_length: int = unpack('I', file.read(4))[0]

                    commit_message_bytes: bytes = file.read(commit_message_length)
                    # print(f"{commit_message_length=:>28}  {commit_message_bytes=}")

                    # Decrypt the commit message
                    decrypted_message: str = SymmetricCryptoHandler.decrypt(
                        encrypted_data=commit_message_bytes,
                        password=self.secret,
                        method=self.symmetric_encryption_type
                    )

                    # Decrypt the commit data
                    commit_data_length: int = unpack('I', file.read(4))[0]
                    
                    commit_data_bytes: bytes = file.read(commit_data_length)
                    # print(f"{commit_data_length=:>31}  {commit_data_bytes=}")

                    # Add the commit to the list
                    commits.append(
                        (hexlify(current_commit_hash).decode(), decrypted_message))

        except ValueError as e:
            raise InvalidEPCFileError(message="Invalid file") from e

        # Log the commit load
        self.logger.info(msg=f"Loaded all commits")

        return commits

    def load_commit_data(
            self,
            *,
            commit_hash: str
    ) -> Tuple[str, PasswordBucket]:
        """
        # pypasscrypt.storagehandler.EPC.load_commit
        -----------------------------------

        Get the commit message and data for a specific commit hash.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `commit_hash`: The commit hash to get data for.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `InvalidEPCFileError` if the file is corrupt.

        ~~~~~~~~~~~~~~~

        Return:
        The commit message and data for the commit hash.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.verify()

        # convert the commit hash to bytes
        commit_hash_bytes: bytes = unhexlify(commit_hash.encode())

        try:

            with open(self.file_path, 'rb+') as file:
                # Skip the first 5 hashes
                file.seek(132 + self.hash_length)

                commit_data: Optional[PasswordBucket] = None

                while not commit_data:
                    # Read the current commit hash
                    current_commit_hash: bytes = file.read(self.hash_length)

                    # Check if the commit hash is valid
                    if not current_commit_hash:
                        self.logger.error(msg="Invalid commit hash")
                        raise ValueError("Invalid commit hash")

                    # Read the commit message
                    commit_message_length: int = unpack('I', file.read(4))[0]
                    commit_message_bytes: bytes = file.read(
                        commit_message_length)

                    # Read the commit data
                    commit_data_length: int = unpack('I', file.read(4))[0]

                    # Check if the commit hash is the required hash
                    if current_commit_hash != commit_hash_bytes:
                        file.seek(commit_data_length, 1)
                        continue

                    # Decrypt the commit data
                    decrypted_message: str = SymmetricCryptoHandler.decrypt(
                        encrypted_data=commit_message_bytes,
                        password=self.secret,
                        method=self.symmetric_encryption_type
                    )

                    # Decrypt the commit data
                    decrypted_data: str = SymmetricCryptoHandler.decrypt(
                        encrypted_data=file.read(commit_data_length),
                        password=self.secret,
                        method=self.symmetric_encryption_type
                    )

                    commit_data = PasswordBucket.from_string(
                        data=decrypted_data)

        except ValueError as e:
            raise InvalidEPCFileError(message="Invalid file") from e

        # Log the commit load
        self.logger.info(
            msg=f"Loaded data from commit - {hexlify(current_commit_hash).decode()}")

        # Return the commit message and data
        return decrypted_message, commit_data

    def revert_to_commit(
            self,
            *,
            commit_hash: str
    ) -> None:
        """
        # pypasscrypt.storagehandler.EPC.revert_to_commit
        ----------------------------------------

        Revert the storage to a specific commit hash.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `commit_hash`: The commit hash to revert to.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        # Verify the EPC object
        self.verify()

        # Create a temporary file
        temp_file_path: str = f"{self.file_path}.tmp"

        with open(self.file_path, 'rb+') as epc_file, open(temp_file_path, 'wb+') as tmp_file:
            tmp_file.write(epc_file.read(132))  # Copy the first 3 hashes

            # Write the current commit hash
            tmp_file.write(unhexlify(commit_hash.encode()))

            epc_file.seek(self.hash_length, 1)  # Skip the current commit hash
            tmp_file.write(epc_file.read())

        # Log the revert
        self.logger.warning(msg=f"Reverted to commit - {commit_hash}")

        # Replace the old file with the new file
        os.replace(temp_file_path, self.file_path)

    def change_secret(
            self,
            *,
            new_secret: str
    ) -> None:
        """
        # pypasscrypt.storagehandler.EPC.change_secret
        -------------------------------------

        Change the secret to encrypt/decrypt the passwords.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `new_secret`: The new password to encrypt/decrypt the passwords.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `InvalidEPCFileError` if the file is corrupt.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.verify()

        # Create a temporary file
        temp_file_path: str = f"{self.file_path}.tmp"

        # Write the new secret to the file
        try:
            with open(self.file_path, 'rb+') as epc_file, open(temp_file_path, 'wb+') as tmp_file:

                # seek to the first commit hash
                tmp_file.seek(0)

                # Copy the first hash
                hashed_file_version: bytes = unhexlify(HashHandler.generate_hash(
                    data=EPC.FILE_VERSION,
                    method="SHA256"
                ).encode())
                # print(f"{len(hashed_file_version)=:>25}  {hashed_file_version=}")
                tmp_file.write(hashed_file_version)

                # Write the new secret hash
                hashed_secret: bytes = unhexlify(HashHandler.generate_hash(
                    data=new_secret,
                    method="SHA256"
                ).encode())
                # print(f"{len(hashed_secret)=:>31}  {hashed_secret=}")
                tmp_file.write(hashed_secret)

                # Write encryption type hash (32 bytes)
                hashed_symmetric_encryption_type: bytes = unhexlify(HashHandler.generate_hash(
                    data=self.symmetric_encryption_type,
                    method="SHA256"
                ).encode())
                # print(f"{len(hashed_symmetric_encryption_type)=:>12}  {hashed_symmetric_encryption_type=}")
                tmp_file.write(hashed_symmetric_encryption_type)

                # Write hash type hash (32 bytes)
                hashed_hash_type: bytes = unhexlify(HashHandler.generate_hash(
                    data=self.hash_type,
                    method="SHA256"
                ).encode())
                # print(f"{len(hashed_hash_type)=:>28}  {hashed_hash_type=}")
                tmp_file.write(hashed_hash_type)
                
                epc_file.seek(128)
                packed_hash_length: bytes = epc_file.read(4)
                # print(f"{len(packed_hash_length)=:>26}  {packed_hash_length=}")
                tmp_file.write(packed_hash_length)

                commit_hash: bytes = epc_file.read(self.hash_length)
                # print(f"{len(commit_hash)=:>33}  {commit_hash=}")
                tmp_file.write(commit_hash)

                while True:
                    current_commit_hash: bytes = epc_file.read(self.hash_length)

                    if not current_commit_hash:
                        break

                    # print(f"{len(current_commit_hash)=:>25}  {current_commit_hash=}")

                    # Read the commit message
                    commit_message_length: int = unpack('I', epc_file.read(4))[0]
                    commit_message: bytes = epc_file.read(commit_message_length)

                    # decrypt the commit message
                    decrypted_message: str = SymmetricCryptoHandler.decrypt(
                        encrypted_data=commit_message,
                        password=self.secret,
                        method=self.symmetric_encryption_type
                    )

                    # Encrypt the commit message with the new secret
                    encrypted_commit_message = SymmetricCryptoHandler.encrypt(
                        data=decrypted_message,
                        password=new_secret,
                        method=self.symmetric_encryption_type
                    )
                    
                    # print(f"{commit_message_length=:>28}  {encrypted_commit_message=}")

                    # Read the commit data
                    commit_data_length: int = unpack('I', epc_file.read(4))[0]
                    commit_data: bytes = epc_file.read(commit_data_length)

                    # Decrypt the commit data
                    decrypted_data: str = SymmetricCryptoHandler.decrypt(
                        encrypted_data=commit_data,
                        password=self.secret,
                        method=self.symmetric_encryption_type
                    )

                    # Encrypt the commit data with the new secret
                    encrypted_commit_data: bytes = SymmetricCryptoHandler.encrypt(
                        data=decrypted_data,
                        password=new_secret,
                        method=self.symmetric_encryption_type
                    )
                    # print(f"{commit_data_length=:>31}  {encrypted_commit_data=}")

                    # Write the new commit to the file
                    tmp_file.write(current_commit_hash)
                    tmp_file.write(pack('I', commit_message_length))
                    tmp_file.write(encrypted_commit_message)
                    tmp_file.write(pack('I', commit_data_length))
                    tmp_file.write(encrypted_commit_data)

        except ValueError as e:
            raise InvalidEPCFileError(message="Invalid file") from e

        # Log the secret change
        self.logger.warning(msg="Changed secret")

        # Replace the old file with the new file
        os.replace(temp_file_path, self.file_path)

        # Update the secret
        self.secret = new_secret

    def change_encryption_type(
            self,
            *,
            new_symmetric_encryption_type: SymmetricEncryptionTypes
    ) -> None:
        """
        # pypasscrypt.storagehandler.EPC.change_encryption_type
        ----------------------------------------------

        Change the encryption type.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `new_symmetric_encryption_type`: The new encryption method to use.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `ValueError` if the file is corrupt.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.verify()

        # Create a temporary file
        temp_file_path: str = f"{self.file_path}.tmp"

        # Write the new encryption type to the file
        with open(self.file_path, 'rb+') as epc_file, open(temp_file_path, 'wb+') as tmp_file:

            # seek to the first commit hash
            tmp_file.seek(0)

            # Write file version (32 bytes)
            hashed_file_version: bytes = unhexlify(HashHandler.generate_hash(
                data=EPC.FILE_VERSION,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_file_version)=:>25}  {hashed_file_version=}")
            tmp_file.write(hashed_file_version)

            # Write password hash (32 bytes)
            hashed_secret: bytes = unhexlify(HashHandler.generate_hash(
                data=self.secret,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_secret)=:>31}  {hashed_secret=}")
            tmp_file.write(hashed_secret)

            # Write encryption type hash (32 bytes)
            hashed_symmetric_encryption_type: bytes = unhexlify(HashHandler.generate_hash(
                data=new_symmetric_encryption_type,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_symmetric_encryption_type)=:>12}  {hashed_symmetric_encryption_type=}")
            tmp_file.write(hashed_symmetric_encryption_type)

            # Write hash type hash (32 bytes)
            hashed_hash_type: bytes = unhexlify(HashHandler.generate_hash(
                data=self.hash_type,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_hash_type)=:>28}  {hashed_hash_type=}")
            tmp_file.write(hashed_hash_type)

            epc_file.seek(128)
            packed_hash_length: bytes = epc_file.read(4)
            # print(f"{len(packed_hash_length)=:>26}  {packed_hash_length=}")
            tmp_file.write(packed_hash_length)

            commit_hash: bytes = epc_file.read(self.hash_length)
            # print(f"{len(commit_hash)=:>33}  {commit_hash=}")
            tmp_file.write(commit_hash)
            
            while True:
                    current_commit_hash: bytes = epc_file.read(self.hash_length)

                    if not current_commit_hash:
                        break

                    # print(f"{len(current_commit_hash)=:>25}  {current_commit_hash=}")

                    # Read the commit message
                    commit_message_length: int = unpack('I', epc_file.read(4))[0]
                    commit_message: bytes = epc_file.read(commit_message_length)

                    # decrypt the commit message
                    decrypted_message: str = SymmetricCryptoHandler.decrypt(
                        encrypted_data=commit_message,
                        password=self.secret,
                        method=self.symmetric_encryption_type
                    )

                    # Encrypt the commit message with the new secret
                    encrypted_commit_message = SymmetricCryptoHandler.encrypt(
                        data=decrypted_message,
                        password=self.secret,
                        method=new_symmetric_encryption_type
                    )
                    
                    # print(f"{commit_message_length=:>28}  {encrypted_commit_message=}")

                    # Read the commit data
                    commit_data_length: int = unpack('I', epc_file.read(4))[0]
                    commit_data: bytes = epc_file.read(commit_data_length)

                    # Decrypt the commit data
                    decrypted_data: str = SymmetricCryptoHandler.decrypt(
                        encrypted_data=commit_data,
                        password=self.secret,
                        method=self.symmetric_encryption_type
                    )

                    # Encrypt the commit data with the new secret
                    encrypted_commit_data: bytes = SymmetricCryptoHandler.encrypt(
                        data=decrypted_data,
                        password=self.secret,
                        method=new_symmetric_encryption_type
                    )
                    # print(f"{commit_data_length=:>31}  {encrypted_commit_data=}")

                    # Write the new commit to the file
                    tmp_file.write(current_commit_hash)
                    tmp_file.write(pack('I', commit_message_length))
                    tmp_file.write(encrypted_commit_message)
                    tmp_file.write(pack('I', commit_data_length))
                    tmp_file.write(encrypted_commit_data)

        # Log the encryption type change
        self.logger.warning(msg="Changed encryption type")

        # Replace the old file with the new file
        os.replace(temp_file_path, self.file_path)

        # Update the encryption type
        self.symmetric_encryption_type = new_symmetric_encryption_type

    def change_hash_type(
            self,
            *,
            new_hash_type: HashTypes
    ) -> None:
        """
        # pypasscrypt.storagehandler.EPC.change_hash_type
        --------------------------------------------

        Change the hash type.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `new_hash_type`: The new hash type to use.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `ValueError` if the file is corrupt.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.verify()

        # Create a temporary file
        temp_file_path: str = f"{self.file_path}.tmp"

        # Write the new hash type to the file
        with open(self.file_path, 'rb+') as epc_file, open(temp_file_path, 'wb+') as tmp_file:

            # seek to the first commit hash
            tmp_file.seek(0)

            # Write file version (32 bytes)
            hashed_file_version: bytes = unhexlify(HashHandler.generate_hash(
                data=EPC.FILE_VERSION,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_file_version)=:>25}  {hashed_file_version=}")
            tmp_file.write(hashed_file_version)

            # Write password hash (32 bytes)
            hashed_secret: bytes = unhexlify(HashHandler.generate_hash(
                data=self.secret,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_secret)=:>31}  {hashed_secret=}")
            tmp_file.write(hashed_secret)

            # Write encryption type hash (32 bytes)
            hashed_symmetric_encryption_type: bytes = unhexlify(HashHandler.generate_hash(
                data=self.symmetric_encryption_type,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_symmetric_encryption_type)=:>12}  {hashed_symmetric_encryption_type=}")
            tmp_file.write(hashed_symmetric_encryption_type)

            # Write hash type hash (32 bytes)
            hashed_hash_type: bytes = unhexlify(HashHandler.generate_hash(
                data=new_hash_type,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_hash_type)=:>28}  {hashed_hash_type=}")
            tmp_file.write(hashed_hash_type)
            
            epc_file.seek(132)

            commit_hash_str: str = hexlify(epc_file.read(self.hash_length)).decode()
            new_commit_hash: bytes = unhexlify(HashHandler.generate_hash(
                data=commit_hash_str,
                method=new_hash_type
            ).encode())

            # Write the new commit hash length
            packed_hash_length: bytes = pack('I', len(new_commit_hash))
            # print(f"{len(packed_hash_length)=:>26}  {packed_hash_length=}")
            tmp_file.write(packed_hash_length)

            # Write the new commit hash
            tmp_file.write(new_commit_hash)            

            while True:
                current_commit_hash = epc_file.read(self.hash_length)
                if not current_commit_hash:
                    break

                # print(f"{len(current_commit_hash)=:>25}  {current_commit_hash=}")

                current_commit_str: str = hexlify(current_commit_hash).decode()
                new_current_commit: bytes = unhexlify(HashHandler.generate_hash(
                    data=current_commit_str,
                    method=new_hash_type
                ).encode())

                if len(new_current_commit) != len(new_commit_hash):
                    raise ValueError("Invalid commit length")

                # Read the commit message
                commit_message_length: int = unpack('I', epc_file.read(4))[0]
                commit_message: bytes = epc_file.read(commit_message_length)

                # Read the commit data
                commit_data_length: int = unpack('I', epc_file.read(4))[0]
                commit_data: bytes = epc_file.read(commit_data_length)
                
                # Write the new commit to the file
                tmp_file.write(new_current_commit)
                tmp_file.write(pack('I', commit_message_length))
                tmp_file.write(commit_message)
                tmp_file.write(pack('I', commit_data_length))
                tmp_file.write(commit_data)

        # Log the hash type change
        self.logger.warning(msg="Changed hash type")

        # Replace the old file with the new file
        os.replace(temp_file_path, self.file_path)

        self.hash_length = len(new_commit_hash)

    def import_data(
            self,
            new_data: PasswordBucket
    ) -> None:
        """
        # pypasscrypt.storagehandler.EPC.import_data
        --------------------------------

        Import data to the storage.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `new_data`: The new data to import.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the data is invalid.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        # validate the datatype of new_data
        if not isinstance(new_data, PasswordBucket):
            raise TypeError("Invalid data input")

        data: PasswordBucket = self.load(f"Importing data.")
        
        for site, username in new_data.get_listings():
            if data.is_username_exists(site=site, username=username):
                data.edit_password(
                    site=site, username=username, password=new_data.get_password(site=site, username=username))
            else:
                data.add_password(
                    site=site, username=username, password=new_data.get_password(site=site, username=username))

        self.save(commit_data=data, commit_message=f"Imported data")

    def export_data(
            self,
            *,
            listings: List[Tuple[str, str]]
    ) -> PasswordBucket:
        """
        # pypasscrypt.storagehandler.EPC.export_data
        --------------------------------

        Export data from the storage.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `listings`: The listings to export.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the listings is invalid.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        The selected listings with their passwords.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        # validate the datatype of listings
        if isinstance(listings, list):
            for site, username in listings:
                if not isinstance(site, str):
                    raise TypeError("Invalid data input")
                if not isinstance(username, str):
                    raise TypeError("Invalid data input")
        else:
            raise TypeError("Invalid data input")

        data: PasswordBucket = self.load(f"Exporting data.")

        export_data: PasswordBucket = PasswordBucket()
        
        for site, username in listings:
            if data.is_username_exists(site=site, username=username):
                export_data.add_password(
                    site=site, username=username, password=data.get_password(site=site, username=username))
            else:
                raise ValueError(f"Site: {site}, Username: {username} not found in the storage.")

        return export_data

    @staticmethod
    def create(
            *,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            hash_type: HashTypes,
            file_path: str
    ) -> str:
        """
        # pypasscrypt.storagehandler.EPC.create
        -------------------------------

        Create a new EPC file.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `secret`: The password to encrypt/decrypt the passwords.
        - `symmetric_encryption_type`: The encryption method to use.
        - `hash_type`: The hash type to use.
        - `file_path`: The file path to store the passwords.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the parameters is invalid.
        - `InvalidSymmetricEncryptionTypeError` if the symmetric encryption type is invalid.
        - `InvalidHashTypeError` if the hash type is invalid.
        - `ValueError` if the file extension is invalid.
        - `FileExistsError` if the file already exists.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        The file path of the new EPC file.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(secret, str):
            raise TypeError("Secret must be a string.")

        if symmetric_encryption_type not in get_args(SymmetricEncryptionTypes):
            raise InvalidSymmetricEncryptionTypeError(
                message=f"Invalid symmetric encryption type: {symmetric_encryption_type}")

        if hash_type not in get_args(HashTypes):
            raise InvalidHashTypeError(
                message=f"Invalid hash type: {hash_type}")

        if not isinstance(file_path, str):
            raise TypeError("File name must be a string.")
        
        if not file_path.endswith(EPC.FILE_EXTENSION):
            raise ValueError(
                f"Only {EPC.FILE_EXTENSION} files are supported.")

        if os.path.exists(file_path):
            raise FileExistsError("File already exists.")
        
        directory: str = os.path.dirname(file_path)

        if directory == "":
            directory = os.getcwd()
        else:
            os.makedirs(directory, exist_ok=True)

        with open(file_path, 'wb+') as file:
            file.seek(0)

            # Write file version (32 bytes)
            hashed_file_version: bytes = unhexlify(HashHandler.generate_hash(
                data=EPC.FILE_VERSION,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_file_version)=:>25}  {hashed_file_version=}")
            file.write(hashed_file_version)

            # Write password hash (32 bytes)
            hashed_secret: bytes = unhexlify(HashHandler.generate_hash(
                data=secret,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_secret)=:>31}  {hashed_secret=}")
            file.write(hashed_secret)

            # Write encryption type hash (32 bytes)
            hashed_symmetric_encryption_type: bytes = unhexlify(HashHandler.generate_hash(
                data=symmetric_encryption_type,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_symmetric_encryption_type)=:>12}  {hashed_symmetric_encryption_type=}")
            file.write(hashed_symmetric_encryption_type)

            # Write hash type hash (32 bytes)
            hashed_hash_type: bytes = unhexlify(HashHandler.generate_hash(
                data=hash_type,
                method="SHA256"
            ).encode())
            # print(f"{len(hashed_hash_type)=:>28}  {hashed_hash_type=}")
            file.write(hashed_hash_type)

            # create a new commit hash
            current_commit_hash: bytes = unhexlify(HashHandler.generate_hash(
                data=datetime.now().isoformat(),
                method=hash_type
            ).encode())

            # write current commit hash length (4 bytes)
            packed_hash_length: bytes = pack('I', len(current_commit_hash))
            # print(f"{len(packed_hash_length)=:>26}  {packed_hash_length=}")
            file.write(packed_hash_length)

            # print("base structure size:                          ", file.tell(), end="\n\n")

            # write current commit hash (32 bytes)
            # print(f"{len(current_commit_hash)=:>25}  {current_commit_hash=}")
            file.write(current_commit_hash)

            # create a new commit hash (32 bytes)
            # print(f"{len(current_commit_hash)=:>25}  {current_commit_hash=}")
            file.write(current_commit_hash)

            # encrypt the commit message
            commit_message: str = "Initial commit"
            encrypted_commit_message = SymmetricCryptoHandler.encrypt(
                data=commit_message,
                password=secret,
                method=symmetric_encryption_type
            )

            # Write commit message length (4 bytes)
            # print(f"{len(encrypted_commit_message)=:>20}  {encrypted_commit_message=}")
            file.write(pack('I', len(encrypted_commit_message)))

            # Write commit message (n bytes)
            file.write(encrypted_commit_message)

            encrypted_data = SymmetricCryptoHandler.encrypt(
                data=json.dumps({}),
                password=secret,
                method=symmetric_encryption_type
            )

            # Write data length (4 bytes)
            # print(f"{len(encrypted_data)=:>30}  {encrypted_data=}")
            file.write(pack('I', len(encrypted_data)))

            # Write data (n bytes)
            file.write(encrypted_data)

        return file_path

    def get_all_sites(self) -> List[str]:
        """
        # pypasscrypt.storagehandler.EPC.get_all_sites
        -----------------------------------

        Get all the sites stored in the EPC file.

        ~~~~~~~~~~~~~~~

        Return:
        The list of sites stored in the EPC file.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        data: PasswordBucket = self.load(f"Getting all sites.")

        return data.get_all_sites()
    
    def get_all_usernames(self) -> List[str]:
        """
        # pypasscrypt.storagehandler.EPC.get_all_usernames
        ---------------------------------------

        Get all the usernames stored in the EPC file.

        ~~~~~~~~~~~~~~~

        Return:
        The list of usernames stored in the EPC file.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        data: PasswordBucket = self.load("Getting all usernames.")

        return data.get_all_usernames()
    
    def get_listings(self) -> List[Tuple[str, str]]:
        """
        # pypasscrypt.storagehandler.EPC.get_listings
        --------------------------------

        Get all the listings stored in the EPC file.

        ~~~~~~~~~~~~~~~

        Return:
        The list of listings stored in the EPC file.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        data: PasswordBucket = self.load("Getting all listings.")

        return data.get_listings()
    
    def is_site_exists(self, *, site: str) -> bool:
        """
        # pypasscrypt.storagehandler.EPC.is_site_exists
        -----------------------------------

        Check if a site exists in the EPC file.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to check for.

        ~~~~~~~~~~~~~~~

        Return:
        True if the site exists, False otherwise.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        data: PasswordBucket = self.load(f"Checking site: {site}")

        return data.is_site_exists(site=site)
    
    def get_usernames_by_site(self, *, site: str) -> List[str]:
        """
        # pypasscrypt.storagehandler.EPC.get_usernames_by_site
        ----------------------------------------------

        Get all the usernames for a specific site stored in the EPC file.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to get usernames for.

        ~~~~~~~~~~~~~~~

        Return:
        The list of usernames for the site stored in the EPC file.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        data: PasswordBucket = self.load(f"Getting usernames for site: {site}")

        return data.get_usernames_by_site(site=site)
    
    def is_username_exists(self, *, site: str, username: str) -> bool:
        """
        # pypasscrypt.storagehandler.EPC.is_username_exists
        ---------------------------------------

        Check if a username exists for a specific site in the EPC file.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to check for.
        - `username`: The username to check for.

        ~~~~~~~~~~~~~~~

        Return:
        True if the username exists, False otherwise.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        data: PasswordBucket = self.load(f"Checking username: {username}")

        return data.is_username_exists(site=site, username=username)
    
    def add_password(self, *, site: str, username: str, password: str) -> None:
        """
        # pypasscrypt.storagehandler.EPC.add_password
        ----------------------------------

        Add a new password to the EPC file.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to add the password to.
        - `username`: The username to add the password to.
        - `password`: The password to add.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the parameters is invalid.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise TypeError("Site must be a string.")

        if not isinstance(username, str):
            raise TypeError("Username must be a string.")

        if not isinstance(password, str):
            raise TypeError("Password must be a string.")

        data: PasswordBucket = self.load(f"Adding password for site: {site}")

        data.add_password(site=site, username=username, password=password)

        self.save(commit_data=data, commit_message=f"Added password for {username} in {site}")

    def edit_password(self, *, site: str, username: str, password: str) -> None:
        """
        # pypasscrypt.storagehandler.EPC.edit_password
        -----------------------------------

        Edit a password in the EPC file.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to edit the password for.
        - `username`: The username to edit the password for.
        - `password`: The new password.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the parameters is invalid.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise TypeError("Site must be a string.")

        if not isinstance(username, str):
            raise TypeError("Username must be a string.")

        if not isinstance(password, str):
            raise TypeError("Password must be a string.")

        data: PasswordBucket = self.load(f"Editing password for site: {site}")

        data.edit_password(site=site, username=username, password=password)

        self.save(commit_data=data, commit_message=f"Edited password for {username} in {site}")

    def remove_password(self, *, site: str, username: str) -> None:
        """
        # pypasscrypt.storagehandler.EPC.remove_password
        -------------------------------------

        Delete a password from the EPC file.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to delete the password from.
        - `username`: The username to delete the password from.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the parameters is invalid.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise TypeError("Site must be a string.")

        if not isinstance(username, str):
            raise TypeError("Username must be a string.")

        data: PasswordBucket = self.load(f"Deleting password for site: {site}")

        data.remove_password(site=site, username=username)

        self.save(commit_data=data, commit_message=f"Deleted password for {username} in {site}")

    def get_password(self, *, site: str, username: str) -> str:
        """
        # pypasscrypt.storagehandler.EPC.get_password
        ----------------------------------

        Get a password from the EPC file.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to get the password from.
        - `username`: The username to get the password from.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the parameters is invalid.

        ~~~~~~~~~~~~~~~

        Return:
        The password for the site and username.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise TypeError("Site must be a string.")

        if not isinstance(username, str):
            raise TypeError("Username must be a string.")

        data: PasswordBucket = self.load(f"Getting password for site: {site}")

        return data.get_password(site=site, username=username)
    
    def get_username_except_site(self, *, site: str) -> List[str]:
        """
        # pypasscrypt.storagehandler.EPC.get_username_except_site
        ----------------------------------

         all usernames other than that of given site.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to ignore.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the parameters is invalid.

        ~~~~~~~~~~~~~~~

        Return:
        the list of all username not in that site.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise TypeError("Site must be a string.")
        
        data: PasswordBucket = self.load(f"Getting all usernames except for site: {site}")
        
        all_usernames = data.get_all_usernames()
        site_usernames = data.get_usernames_by_site(site=site)

        return list(set(all_usernames) - set(site_usernames))
        
    def __str__(self) -> str:
        return str(self.load("Display the EPC object."))


class EPT:
    """
    # pypasscrypt.storagehandler.EPT
    ------------------------

    The EPT class to handle the storage of the EPT file.

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    FILE_VERSION: str = "EPTv1.0"
    """
    # pypasscrypt.storagehandler.EPT.FILE_VERSION
    -----------------------------------
    
    The file version of the EPT file.
    
    ~~~~~~~~~~~~~~~
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    FILE_EXTENSION: str = "ept"
    """
    # pypasscrypt.storagehandler.EPT.FILE_EXTENSION
    -----------------------------------

    The file extension of the EPT file.

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def create(
        *,
        data: PasswordBucket,
        secret: str,
        symmetric_encryption_type: SymmetricEncryptionTypes,
        file_path: str
    ) -> str:
        """
        # pypasscrypt.storagehandler.EPT.create
        -------------------------------

        Create a new EPT file.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `data`: The data to store in the EPT file.
        - `secret`: The password to encrypt/decrypt the passwords.
        - `symmetric_encryption_type`: The encryption method to use.
        - `file_path`: The file path to store the passwords.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the parameters is invalid.
        - `InvalidSymmetricEncryptionTypeError` if the symmetric encryption type is invalid.
        - `InvalidPasswordBucketError` if the data is invalid
        - `ValueError` if the file extension is invalid.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        The file path of the new EPT file.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not isinstance(secret, str):
            raise TypeError("Secret must be a string.")

        if symmetric_encryption_type not in get_args(SymmetricEncryptionTypes):
            raise InvalidSymmetricEncryptionTypeError(
                message=f"Invalid symmetric encryption type: {symmetric_encryption_type}")

        if not isinstance(data, PasswordBucket):
            raise InvalidPasswordBucketError("Invalid data")
        
        if not file_path.endswith(EPT.FILE_EXTENSION):
            raise ValueError(
                f"Only {EPT.FILE_EXTENSION} files are supported.")

        counter: int = 1
        new_file_path: str = file_path
        while os.path.exists(new_file_path):
            new_file_path = file_path.replace(EPT.FILE_EXTENSION, f"_{counter}{EPT.FILE_EXTENSION}")


        
        directory: str = os.path.dirname(new_file_path)

        if directory == "":
            directory = os.getcwd()
        else:
            os.makedirs(directory, exist_ok=True)

        with open(new_file_path, 'wb+') as file:
            file.seek(0)

            # Write file version (32 bytes)
            file.write(unhexlify(HashHandler.generate_hash(
                data=EPT.FILE_VERSION,
                method="SHA256"
            ).encode()))

            # Write password hash (32 bytes)
            file.write(unhexlify(HashHandler.generate_hash(
                data=secret,
                method="SHA256"
            ).encode()))

            # Write encryption type hash (32 bytes)
            file.write(unhexlify(HashHandler.generate_hash(
                data=symmetric_encryption_type,
                method="SHA256"
            ).encode()))

            encrypted_data = SymmetricCryptoHandler.encrypt(
                data=str(data),
                password=secret,
                method=symmetric_encryption_type
            )

            # Write data length (4 bytes)
            file.write(pack('I', len(encrypted_data)))

            # Write data (n bytes)
            file.write(encrypted_data)

        return new_file_path

    @staticmethod
    def load(
        *,
        file_path: str,
        secret: str
    ) -> PasswordBucket:
        """
        # pypasscrypt.storagehandler.EPT.load
        -----------------------------

        Load the data from the EPT file.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `file_path`: The path of the EPT file.
        - `secret`: The password to encrypt/decrypt the passwords.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the parameters is invalid.
        - `ValueError` if the file is corrupt.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        The data stored in the EPT file.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not isinstance(secret, str):
            raise TypeError("Secret must be a string.")

        if not isinstance(file_path, str):
            raise TypeError("File path must be a string.")

        if not os.path.exists(file_path):
            raise FileNotFoundError("File not found.")
        
        try:
            with open(file_path, 'rb') as file:
                file.seek(0)

                # Verify the file version
                if not HashHandler.verify_hash(
                    data=EPT.FILE_VERSION,
                    hash_data=hexlify(file.read(32)).decode(),
                    method="SHA256"
                ):
                    raise ValueError("Invalid file version")

                # Verify the password hash
                if not HashHandler.verify_hash(
                    data=secret,
                    hash_data=hexlify(file.read(32)).decode(),
                    method="SHA256"
                ):
                    raise ValueError("Invalid password")

                # Read the encryption type hash
                encryption_type_hash: bytes = file.read(32)

                encryption_method: Optional[SymmetricEncryptionTypes] = None

                for encryption_type in get_args(SymmetricEncryptionTypes):
                    if HashHandler.verify_hash(
                        data=encryption_type,
                        hash_data=hexlify(encryption_type_hash).decode(),
                        method="SHA256"
                    ):
                        encryption_method = encryption_type
                        break

                if not encryption_method:
                    raise ValueError("Invalid encryption type")

                # Read the data length
                data_length: int = unpack('I', file.read(4))[0]

                # Read the data
                encrypted_data: bytes = file.read(data_length)

                # Decrypt the data
                decrypted_data: str = SymmetricCryptoHandler.decrypt(
                    encrypted_data=encrypted_data,
                    password=secret,
                    method=encryption_method
                )
                
                try:
                    data: PasswordBucket = PasswordBucket.from_string(data=decrypted_data)
                except InvalidPasswordBucketError as e:
                    raise ValueError("Invalid data") from e
                        
        except ValueError as e:
            raise InvalidEPTFileError(message="Invalid file") from e

        return data
