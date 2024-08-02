"""
# pypasscrypt.storage
-------------------

The module to manage password storage.


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
    Union,
    get_args
)
from pypasscrypt.cryptohandler import (
    HashingHandler,
    HashingTypes,
    SymmetricCryptoHandler,
    SymmetricEncryptionTypes
)
from pypasscrypt.logginghandler import (
    LoggerHandler, 
    LoggerTypes
)


class EPC:
    """
    # pypasscrypt.storage.EPC
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
    # pypasscrypt.storage.EPC.FILE_VERSION
    -----------------------------------

    The file version of the EPC file.

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    FILE_EXTENSION: str = "epc"
    """
    # pypasscrypt.storage.EPC.FILE_EXTENSION
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
            hashing_type: HashingTypes,
            logger_type: LoggerTypes
    ) -> None:
        """
        # pypasscrypt.storage.EPC.__init__
        --------------------------------

        Initialize the EPC object.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `file_path`: The file path to manage password storage.
        - `secret`: The password to encrypt/decrypt the passwords.
        - `symmetric_encryption_type`: The encryption method to use.
        - `hashing_type`: The hashing method to use.
        - `logger_type`: The logger type.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the parameters are invalid.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(file_path, str):
            raise TypeError("File path must be a string.")
        
        if not file_path.endswith(self.FILE_EXTENSION):
            raise ValueError(f"Only {self.FILE_EXTENSION} files are supported.")
        
        if not isinstance(secret, str):
            raise TypeError("Secret must be a string.")
        
        if symmetric_encryption_type not in get_args(SymmetricEncryptionTypes):
            raise TypeError("Symmetric encryption type must be a SymmetricEncryptionTypes.")
        
        if hashing_type not in get_args(HashingTypes):
            raise TypeError("Hashing type must be a HashingTypes.")
        
        if logger_type not in get_args(LoggerTypes):
            raise TypeError("Logger type must be a LoggerTypes.")

        self.file_path: str = file_path
        self.secret: str = secret
        self.symmetric_encryption_type: SymmetricEncryptionTypes = symmetric_encryption_type
        self.hashing_type: HashingTypes = hashing_type
        self.logger: LoggerHandler = LoggerHandler(logger_type=logger_type)

        # Verify the EPC object
        self.verify()


    def __enter__(self) -> 'EPC':
        """
        # pypasscrypt.storage.EPC.__enter__
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
        # pypasscrypt.storage.EPC.__exit__
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
            self.logger.error(message=str(exc_value))

        raise exc_value.with_traceback(exc_traceback) from exc_type

    

    def verify(self) -> None:
        """
        # pypasscrypt.storage.EPC.verify
        -------------------------------

        Verify the EPC file against provided details.

        ~~~~~~~~~~~~~~~

        Raise:
        ------- 
        - `ValueError` if the file is invalid.
        - `FileNotFoundError` if the file is not found.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not os.path.exists(self.file_path):
            self.logger.error(message=f"File not found: {self.file_path}")
            raise FileNotFoundError(f"File not found: {self.file_path}")

        try:
            with open(self.file_path, 'rb+') as file:
                file.seek(0)

                # Verify file version (32 bytes)
                if not HashingHandler.verify_hash(
                        raw_str=self.FILE_VERSION,
                        method=self.hashing_type,
                        hash_bytes=file.read(32)
                ):
                    self.logger.error(message="Invalid file version")
                    raise ValueError("Invalid file version")

                # Verify file hash (32 bytes)
                elif not HashingHandler.verify_hash(
                        raw_str=self.secret,
                        method=self.hashing_type,
                        hash_bytes=file.read(32)
                ):
                    self.logger.error(message="Invalid password")
                    raise ValueError("Invalid password")

                # Verify encryption type (32 bytes)
                elif not HashingHandler.verify_hash(
                        raw_str=self.symmetric_encryption_type,
                        method=self.hashing_type,
                        hash_bytes=file.read(32)
                ):
                    self.logger.error(message="Invalid encryption type")
                    raise ValueError("Invalid encryption type")

        except ValueError as e:
            raise ValueError("Invalid file") from e

    def load(self, reason: str) -> Dict[str, Dict[str, str]]:
        """
        # pypasscrypt.storage.EPC.load
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

        # Get the current commit hash
        with open(self.file_path, 'rb+') as file:
            file.seek(32 * 3)  # Skip the first 3 hashes
            current_commit_hash: bytes = file.read(32)

        # Get the data for the current commit hash
        data: Tuple[str, Dict[str, Dict[str, str]]] = self.load_commit_data(
            commit_hash=hexlify(current_commit_hash).decode())
        
        # Log the data load
        self.logger.info(message=f"Loaded data for: {reason}")

        return data[1]

    def save(
            self,
            *,
            commit_data: Dict[str, Dict[str, str]],
            commit_message: str
    ) -> None:
        """
        # pypasscrypt.storage.EPC.save
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
            epc_file.seek(32 * 4)  # Skip the first 4 hashes

            # Write the file version hash
            tmp_file.write(
                HashingHandler.generate_hash(
                    raw_str=self.FILE_VERSION,
                    method=self.hashing_type
                )
            )

            # Write the password hash
            tmp_file.write(
                HashingHandler.generate_hash(
                    raw_str=self.secret,
                    method=self.hashing_type
                )
            )

            # Write the encryption type hash
            tmp_file.write(
                HashingHandler.generate_hash(
                    raw_str=self.symmetric_encryption_type,
                    method=self.hashing_type
                )
            )

            # create a new commit hash
            new_commit_hash: bytes = HashingHandler.generate_hash(
                raw_str=datetime.now().isoformat(),
                method=self.hashing_type
            )

            # encrypt the message
            encrypted_message: bytes = SymmetricCryptoHandler.encrypt(
                data=commit_message,
                password=self.secret,
                method=self.symmetric_encryption_type
            )

            # encrypt the data
            encrypted_data: bytes = SymmetricCryptoHandler.encrypt(
                data=commit_data,
                password=self.secret,
                method=self.symmetric_encryption_type
            )

            # Write the new commit hash
            tmp_file.write(new_commit_hash)

            # Write the new commit
            tmp_file.write(new_commit_hash)
            tmp_file.write(pack('I', len(encrypted_message)))
            tmp_file.write(encrypted_message)
            tmp_file.write(pack('I', len(encrypted_data)))
            tmp_file.write(encrypted_data)

            # Write the old data
            epc_file.seek(128)
            tmp_file.write(epc_file.read())

        # Log the commit save
        self.logger.info(message=commit_message)
        self.logger.info(
            message=f"Saved data to new commit - {hexlify(new_commit_hash).decode()}",
            logger_type=self.logger_type
        )

        # Replace the old file with the new file
        os.replace(temp_file_path, self.file_path)

    def load_commits(self) -> List[Tuple[str, str]]:
        """
        # pypasscrypt.storage.EPC.load_commits
        ------------------------------------

        Load all the commits from the EPC object.

        ~~~~~~~~~~~~~~~

        Raise:
        ------- 
        - `ValueError` if the file is corrupt.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        The list of commits along with hash, message in the EPC object.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.verify()

        with open(self.file_path, 'rb+') as file:
            file.seek(32 * 4)  # Skip the first 4 hashes

            commits: List[Tuple[str, str]] = []

            while True:
                # Read the current commit hash
                current_commit_hash: bytes = file.read(32)

                # Check if the commit hash is valid
                if not current_commit_hash:
                    break

                # Read the commit message
                commit_message_length: int = unpack('I', file.read(4))[0]

                # Decrypt the commit message
                decrypted_message: Union[Dict[str, Dict[str, str]], str] = SymmetricCryptoHandler.decrypt(
                    encrypted_data=file.read(commit_message_length),
                    password=self.secret,
                    method=self.symmetric_encryption_type
                )

                # Check if the commit message is valid
                if isinstance(decrypted_message, str):
                    commit_message = decrypted_message
                else:
                    self.logger.error(message="Invalid commit message")
                    raise ValueError("Invalid commit message")

                # Decrypt the commit data
                commit_data_length: int = unpack('I', file.read(4))[0]
                file.seek(commit_data_length, 1)

                # Add the commit to the list
                commits.append(
                    (hexlify(current_commit_hash).decode(), commit_message))

        # Log the commit load
        self.logger.info(message=f"Loaded all commits")

        return commits

    def load_commit_data(
            self,
            *,
            commit_hash: str
    ) -> Tuple[str, Dict[str, Dict[str, str]]]:
        """
        # pypasscrypt.storage.EPC.load_commit
        -----------------------------------

        Get the commit message and data for a specific commit hash.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `commit_hash`: The commit hash to get data for.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `ValueError` if the file is corrupt.

        ~~~~~~~~~~~~~~~

        Return:
        The commit message and data for the commit hash.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.verify()

        # convert the commit hash to bytes
        commit_hash_bytes: bytes = unhexlify(commit_hash.encode())

        with open(self.file_path, 'rb+') as file:
            # Skip the first 4 hashes
            file.seek(32 * 4)

            commit_data: Optional[Dict[str, Dict[str, str]]] = None

            while not commit_data:
                # Read the current commit hash
                current_commit_hash: bytes = file.read(32)

                # Check if the commit hash is valid
                if not current_commit_hash:
                    self.logger.error(message="Invalid commit hash")
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
                decrypted_message: Union[Dict[str, Dict[str, str]], str] = SymmetricCryptoHandler.decrypt(
                    encrypted_data=commit_message_bytes,
                    password=self.secret,
                    method=self.symmetric_encryption_type
                )

                # Check if the commit message is valid
                if isinstance(decrypted_message, str):
                    commit_message = decrypted_message
                else:
                    self.logger.error(message="Invalid commit message")
                    raise ValueError("Invalid commit message")

                # Decrypt the commit data
                decrypted_data: Union[Dict[str, Dict[str, str]], str] = SymmetricCryptoHandler.decrypt(
                    encrypted_data=file.read(commit_data_length),
                    password=self.secret,
                    method=self.symmetric_encryption_type
                )

                # Check if the commit data is valid
                if isinstance(decrypted_data, dict):
                    commit_data = decrypted_data
                else:
                    self.logger.error(message="Invalid commit data")
                    raise ValueError("Invalid commit data")

        # Log the commit load
        self.logger.info(
            message=f"Loaded data from commit - {hexlify(current_commit_hash).decode()}",
            logger_type=self.logger_type
        )

        # Return the commit message and data
        return commit_message, commit_data

    def revert_to_commit(
            self,
            *,
            commit_hash: str
    ) -> None:
        """
        # pypasscrypt.storage.EPC.revert_to_commit
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
            tmp_file.write(epc_file.read(32 * 3))  # Copy the first 3 hashes

            # Write the current commit hash
            tmp_file.write(unhexlify(commit_hash.encode()))

            epc_file.seek(32)  # Skip the current commit hash
            tmp_file.write(epc_file.read())

        # Log the revert
        self.logger.warning(
            message=f"Reverted to commit - {commit_hash}")

        # Replace the old file with the new file
        os.replace(temp_file_path, self.file_path)

    def change_secret(
            self,
            *,
            new_secret: str
    ) -> None:
        """
        # pypasscrypt.storage.EPC.change_secret
        -------------------------------------

        Change the secret to encrypt/decrypt the passwords.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `new_secret`: The new password to encrypt/decrypt the passwords.

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

        # Write the new secret to the file
        with open(self.file_path, 'rb+') as epc_file, open(temp_file_path, 'wb+') as tmp_file:

            # seek to the first commit hash
            epc_file.seek(0)
            tmp_file.seek(0)

            # Copy the first hash
            tmp_file.write(epc_file.read(32))

            # Write the new secret hash
            tmp_file.write(
                HashingHandler.generate_hash(raw_str=new_secret, method=self.hashing_type))

            # skip the next hash
            epc_file.seek(32 * 2)

            # Copy the last 2 hashes
            tmp_file.write(epc_file.read(32 * 2))

            # skip the next hash
            epc_file.seek(32 * 4)

            while True:
                commit_hash: bytes = epc_file.read(32)
                if not commit_hash:
                    break

                # Read the commit message
                commit_message_length: int = unpack('I', epc_file.read(4))[0]
                commit_message: bytes = epc_file.read(commit_message_length)

                # decrypt the commit message
                decrypted_message: Union[Dict[str, Dict[str, str]], str] = SymmetricCryptoHandler.decrypt(
                    encrypted_data=commit_message,
                    password=self.secret,
                    method=self.symmetric_encryption_type
                )

                if not isinstance(decrypted_message, str):
                    self.logger.error(message="Invalid commit message")
                    raise ValueError("Invalid commit message")

                # Encrypt the commit message with the new secret
                encrypted_message: bytes = SymmetricCryptoHandler.encrypt(
                    data=decrypted_message,
                    password=new_secret,
                    method=self.symmetric_encryption_type
                )

                # Read the commit data
                commit_data_length: int = unpack('I', epc_file.read(4))[0]
                commit_data: bytes = epc_file.read(commit_data_length)

                # Decrypt the commit data
                decrypted_data: Union[Dict[str, Dict[str, str]], str] = SymmetricCryptoHandler.decrypt(
                    encrypted_data=commit_data,
                    password=self.secret,
                    method=self.symmetric_encryption_type
                )

                if not isinstance(decrypted_data, dict):
                    self.logger.error(message="Invalid commit data")
                    raise ValueError("Invalid commit data")

                # Encrypt the commit data with the new secret
                encrypted_data: bytes = SymmetricCryptoHandler.encrypt(
                    data=decrypted_data,
                    password=new_secret,
                    method=self.symmetric_encryption_type
                )

                # Write the new commit to the file
                tmp_file.write(commit_hash)
                tmp_file.write(pack('I', len(encrypted_message)))
                tmp_file.write(encrypted_message)
                tmp_file.write(pack('I', len(encrypted_data)))
                tmp_file.write(encrypted_data)

        # Log the secret change
        self.logger.warning(message="Changed secret")

        # Replace the old file with the new file
        os.replace(temp_file_path, self.file_path)

    def change_encryption_type(
            self,
            *,
            new_symmetric_encryption_type: SymmetricEncryptionTypes
    ) -> None:
        """
        # pypasscrypt.storage.EPC.change_encryption_type
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
            epc_file.seek(0)
            tmp_file.seek(0)

            # Copy the first 2 hashes
            tmp_file.write(epc_file.read(32 * 2))

            # Write the new encryption type hash
            tmp_file.write(HashingHandler.generate_hash(
                raw_str=new_symmetric_encryption_type,
                method=self.hashing_type
            ))

            epc_file.seek(32 * 3)

            tmp_file.write(epc_file.read(32))
            epc_file.seek(32 * 4)
            tmp_file.seek(32 * 4)
            while True:
                commit_hash = epc_file.read(32)
                if not commit_hash:
                    break

                # Read the commit message
                commit_message_length: int = unpack('I', epc_file.read(4))[0]
                commit_message: bytes = epc_file.read(commit_message_length)

                # Decrypt the commit message
                decrypted_message: Union[Dict[str, Dict[str, str]], str] = SymmetricCryptoHandler.decrypt(
                    encrypted_data=commit_message,
                    password=self.secret,
                    method=self.symmetric_encryption_type
                )

                if not isinstance(decrypted_message, str):
                    self.logger.error(message="Invalid commit message")
                    raise ValueError("Invalid commit message")

                # Encrypt the commit message with the new encryption type
                encrypted_message: bytes = SymmetricCryptoHandler.encrypt(
                    data=decrypted_message,
                    password=self.secret,
                    method=new_symmetric_encryption_type
                )

                # Read the commit data
                commit_data_length: int = unpack('I', epc_file.read(4))[0]
                commit_data: bytes = epc_file.read(commit_data_length)

                # Decrypt the commit data
                decrypted_data: Union[Dict[str, Dict[str, str]], str] = SymmetricCryptoHandler.decrypt(
                    encrypted_data=commit_data,
                    password=self.secret,
                    method=self.symmetric_encryption_type
                )

                if not isinstance(decrypted_data, dict):
                    self.logger.error(message="Invalid commit data")
                    raise ValueError("Invalid commit data")

                # Encrypt the commit data with the new encryption type
                encrypted_data = SymmetricCryptoHandler.encrypt(
                    data=decrypted_data,
                    password=self.secret,
                    method=new_symmetric_encryption_type
                )

                # Write the new commit to the file
                tmp_file.write(commit_hash)
                tmp_file.write(pack('I', len(encrypted_message)))
                tmp_file.write(encrypted_message)
                tmp_file.write(pack('I', len(encrypted_data)))
                tmp_file.write(encrypted_data)

        # Log the encryption type change
        self.logger.warning(message="Changed encryption type")

        # Replace the old file with the new file
        os.replace(temp_file_path, self.file_path)

    def get_all_sites(self) -> List[str]:
        """
        # pypasscrypt.storage.EPC.get_all_sites
        --------------------------------

        Get all the sites stored in the storage.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        The list of sites in the storage.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        return list(self.load("Getting all sited.").keys())

    def get_listings(self) -> List[Tuple[str, str]]:
        """
        # pypasscrypt.storage.EPC.get_listings
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

        data: Dict[str, Dict[str, str]] = self.load("Getting all listings.")

        return [(site, username) for site in data for username in data[site]]

    def is_site_exists(
            self,
            *,
            site: str
    ) -> bool:
        """
        # pypasscrypt.storage.EPC.is_site_exists
        --------------------------------

        Check if a site exists in the storage.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to check.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        If the site exists in the storage.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise TypeError("Site name must be a string.")

        return site in self.load(f"Checking if {site} exists.").keys()

    def get_usernames(
            self,
            *,
            site: str
    ) -> List[str]:
        """
        # pypasscrypt.storage.EPC.get_usernames
        --------------------------------
        
        Get the usernames for a specific site.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `site`: The site to get data for.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `ValueError` if the site is not found.
        - `TypeError` if the site is not a string.

        ~~~~~~~~~~~~~~~

        Return:
        The list of usernames for the site.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise TypeError("Site name must be a string.")
        
        data: Dict[str, Dict[str, str]] = self.load(f"Getting usernames for {site}.")

        if site not in data:
            self.logger.error(message=f"Site not found: {site}")
            raise ValueError(f"Site not found: {site}")
        
        return list(data[site].keys())

    def is_username_exists(
            self,
            *,
            site: str,
            username: str
    ) -> bool:
        """
        # pypasscrypt.storage.EPC.is_username_exists
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
        - `ValueError` if the site is not found.
        - `TypeError` if the site or username is not a string.

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

        data: Dict[str, Dict[str, str]] = self.load(f"Checking if {username} exists in {site}.")

        if site not in data:
            self.logger.error(message=f"Site not found: {site}")
            raise ValueError(f"Site not found: {site}")

        return username in data[site]

    def add_password(
            self,
            *,
            site: str,
            username: str,
            password: str
    ) -> None:
        """
        # pypasscrypt.storage.EPC.add_password
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
        - `TypeError` if the site, username or password is not a string.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise TypeError("Site name must be a string.")

        if not isinstance(username, str):
            raise TypeError("Username name must be a string.")

        if not isinstance(password, str):
            raise TypeError("Password name must be a string.")

        data: Dict[str, Dict[str, str]] = self.load(f"Adding password for {username} at {site}.")

        if site not in data:
            data[site] = {}

        data[site][username] = password

        self.save(commit_data=data, commit_message=f"Added password for {username} at {site}")

    def get_password(
            self,
            *,
            site: str,
            username: str
    ) -> str:
        """
        # pypasscrypt.storage.EPC.get_password
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
        - `ValueError` if the site or username is not found.
        - `TypeError` if the site or username is not a string.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        The password for the site and username.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise TypeError("Site name must be a string.")

        if not isinstance(username, str):
            raise TypeError("Username name must be a string.")

        data: Dict[str, Dict[str, str]] = self.load(f"Getting password of {username} in {site}.")

        if site not in data:
            self.logger.error(message=f"Site not found: {site}")
            raise ValueError(f"Site not found: {site}")
        
        if username not in data[site]:
            self.logger.error(message=f"Username not found: {username} in {site}")
            raise ValueError(f"Username not found: {username} in {site}")

        return data[site][username]

    def edit_password(
            self,
            *,
            site: str,
            username: str,
            password: str
    ) -> None:
        """
        # pypasscrypt.storage.EPC.edit_password
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
        - `ValueError` if site or username not found in the storage.
        - `TypeError` if site, username or password is not a string.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise TypeError("Site name must be a string.")

        if not isinstance(username, str):
            raise TypeError("Username name must be a string.")

        if not isinstance(password, str):
            raise TypeError("Password name must be a string.")

        data: Dict[str, Dict[str, str]] = self.load(f"Editing password for {username} at {site}.")

        if site not in data:
            self.logger.error(message=f"Site not found: {site}")
            raise ValueError(f"Site not found: {site}")

        if username not in data[site]:
            self.logger.error(message=f"Username not found: {username}")
            raise ValueError(f"Username not found: {username}")

        data[site][username] = password

        self.save(commit_data=data, commit_message=f"Edited password for {username} at {site}")

    def remove_password(
            self,
            *,
            site: str,
            username: str
    ) -> None:
        """
        # pypasscrypt.storage.EPC.remove_password
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
        - `ValueError` if site or username not found in the storage.
        - `TypeError` if site or username is not a string.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(site, str):
            raise TypeError("Site name must be a string.")

        if not isinstance(username, str):
            raise TypeError("Username name must be a string.")

        data: Dict[str, Dict[str, str]] = self.load(f"Removing password for {username} at {site}.")

        if site not in data:
            self.logger.error(message=f"Site not found: {site}")
            raise ValueError(f"site not found: {site}")

        if username not in data[site]:
            self.logger.error(message=f"Username not found: {username}")
            raise ValueError(f"Username not found: {username}")

        del data[site][username]

        if len(data[site]) == 0:
            del data[site]

        self.save(commit_data=data, commit_message=f"Removed password for {username} at {site}")

    def import_data(
            self,
            new_data: Dict[str, Dict[str, str]]
    ) -> None:
        """
        # pypasscrypt.storage.EPC.import_data
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
        if isinstance(new_data, dict):
            for site, details in new_data.items():
                if not isinstance(site, str):
                    raise TypeError("Invalid data input")
                if isinstance(details, dict):
                    for username, password in details.items():
                        if not isinstance(username, str):
                            raise TypeError("Invalid data input")
                        
                        if not isinstance(password, str):
                            raise TypeError("Invalid data input")  
                else:
                    raise TypeError("Invalid data input")
        else:
            raise TypeError("Invalid data input")

        data: Dict[str, Dict[str, str]] = self.load(f"Importing data.")

        for site in new_data:
            if site not in data:
                data[site] = {}

            for username in new_data[site]:
                data[site][username] = new_data[site][username]
                
        self.save(commit_data=data, commit_message=f"Imported data")

    def export_data(
            self,
            *,
            listings: List[Tuple[str, str]]
    ) -> Dict[str, Dict[str, str]]:
        """
        # pypasscrypt.storage.EPC.export_data
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
        
        data: Dict[str, Dict[str, str]] = self.load(f"Exporting data.")

        export_data: Dict[str, Dict[str, str]] = {}
        for site, username in listings:
            if site not in export_data:
                export_data[site] = {}

            export_data[site][username] = data[site][username]

        return export_data

    @staticmethod
    def create(
            *,
            directory: str,
            file_name: str,
            extension: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            hashing_type: HashingTypes
    ) -> str:
        """
        # pypasscrypt.storage.EPC.create
        -------------------------------

        Create a new EPC file.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `directory`: The directory to store the EPC file.
        - `file_name`: The name of the EPC file.
        - `extension`: The extension of the EPC file.
        - `secret`: The password to encrypt/decrypt the passwords.
        - `symmetric_encryption_type`: The encryption method to use.
        - `hashing_type`: The hashing method to use.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the parameters is invalid.

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
            raise TypeError("Symmetric encryption type must be a SymmetricEncryptionTypes object.")
        
        if hashing_type not in get_args(HashingTypes):
            raise TypeError("Hashing type must be a HashingTypes object.")
        
        if not isinstance(directory, str):
            raise TypeError("Directory must be a string.")
        
        if not isinstance(file_name, str):
            raise TypeError("File name must be a string.")
        
        if not isinstance(extension, str):
            raise TypeError("Extension must be a string.")

        file_hash = hexlify(HashingHandler.generate_hash(
            raw_str=datetime.now().isoformat(),
            method=hashing_type)).decode('utf-8')
        file_name = f"{file_name}_{file_hash}.{extension}"
        file_path = os.path.join(directory, file_name)
        os.makedirs(directory, exist_ok=True)

        with open(file_path, 'wb+') as file:
            file.seek(0)

            # Write file version (32 bytes)
            file.write(HashingHandler.generate_hash(
                method=hashing_type,
                raw_str=EPC.FILE_VERSION
            ))

            # Write password hash (32 bytes)
            file.write(HashingHandler.generate_hash(
                method=hashing_type,
                raw_str=secret
            ))

            # Write encryption type hash (32 bytes)
            file.write(HashingHandler.generate_hash(
                method=hashing_type,
                raw_str=symmetric_encryption_type
            ))

            current_commit_info = datetime.now().isoformat()

            # write current commit hash (32 bytes)
            file.write(HashingHandler.generate_hash(
                method=hashing_type,
                raw_str=current_commit_info
            ))

            # create a new commit hash (32 bytes)
            file.write(HashingHandler.generate_hash(
                method=hashing_type,
                raw_str=current_commit_info
            ))

            # encrypt the commit message
            commit_message: str = "Initial commit"
            encrypted_commit_message = SymmetricCryptoHandler.encrypt(
                data=commit_message,
                password=secret,
                method=symmetric_encryption_type
            )

            # Write commit message length (4 bytes)
            file.write(pack('I', len(encrypted_commit_message)))

            # Write commit message (n bytes)
            file.write(encrypted_commit_message)

            encrypted_data = SymmetricCryptoHandler.encrypt(
                data={},
                password=secret,
                method=symmetric_encryption_type
            )

            # Write data length (4 bytes)
            file.write(pack('I', len(encrypted_data)))

            # Write data (n bytes)
            file.write(encrypted_data)

        return file_path


class EPT:
    """
    # pypasscrypt.storage.EPT
    ------------------------

    The EPT class to handle the storage of the EPT file.

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    FILE_VERSION: str = "EPTv1.0"
    """
    # pypasscrypt.storage.EPT.FILE_VERSION
    -----------------------------------
    
    The file version of the EPT file.
    
    ~~~~~~~~~~~~~~~
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    FILE_EXTENSION: str = "ept"
    """
    # pypasscrypt.storage.EPT.FILE_EXTENSION
    -----------------------------------

    The file extension of the EPT file.

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            hashing_type: HashingTypes,
            logger_type: LoggerTypes
    ) -> None:
        """
        # pypasscrypt.storage.EPT.__init__
        --------------------------------

        Initialize the EPT object.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `file_path`: The file path of the EPT file.
        - `secret`: The password to encrypt/decrypt the passwords.
        - `symmetric_encryption_type`: The encryption method to use.
        - `hashing_type`: The hashing method to use.
        - `logger_type`: The logger type to use.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `TypeError` if the parameters is invalid.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(file_path, str):
            raise TypeError("File path must be a string.")
        
        if not file_path.endswith(EPT.FILE_EXTENSION):
            raise ValueError("Invalid file extension.")
        
        if not isinstance(secret, str):
            raise TypeError("Secret must be a string.")
        
        if symmetric_encryption_type not in get_args(SymmetricEncryptionTypes):
            raise TypeError("Symmetric encryption type must be a SymmetricEncryptionTypes object.")
        
        if hashing_type not in get_args(HashingTypes):
            raise TypeError("Hashing type must be a HashingTypes object.")
        
        if logger_type not in get_args(LoggerTypes):
            raise TypeError("Logger type must be a LoggerTypes object.")
            
        self.file_path: str = file_path
        self.secret: str = secret
        self.symmetric_encryption_type: SymmetricEncryptionTypes = symmetric_encryption_type
        self.hashing_type: HashingTypes = hashing_type
        self.logger_type: LoggerTypes = logger_type

    def verify(self) -> None:
        """
        # pypasscrypt.storage.EPT.verify
        ------------------------------

        Verify the EPT object.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `ValueError` if the file is corrupt.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        with open(self.file_path, 'rb') as file:
            file.seek(0)

            # Read the file version
            file_version: bytes = file.read(32)

            if file_version != HashingHandler.generate_hash(
                    method=self.hashing_type,
                    raw_str=EPT.FILE_VERSION
            ):
                raise ValueError("Invalid file version")

            # Read the password hash
            password_hash: bytes = file.read(32)

            if password_hash != HashingHandler.generate_hash(
                    method=self.hashing_type,
                    raw_str=self.secret
            ):
                raise ValueError("Invalid password")

            # Read the encryption type hash
            encryption_type_hash: bytes = file.read(32)

            if encryption_type_hash != HashingHandler.generate_hash(
                    method=self.hashing_type,
                    raw_str=self.symmetric_encryption_type
            ):
                raise ValueError("Invalid encryption type")
            
    def load(self, message: str) -> Dict[str, Dict[str, str]]:
        """
        # pypasscrypt.storage.EPT.load
        ----------------------------

        Load the data from the EPT object.

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to log.

        ~~~~~~~~~~~~~~~

        Raise:
        -------
        - `ValueError` if the file is corrupt.

        ~~~~~~~~~~~~~~~

        Return: 
        -------
        The data from the EPT object.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.verify()

        with open(self.file_path, 'rb') as file:
            file.seek(32 * 3)