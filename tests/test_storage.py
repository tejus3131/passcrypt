"""
pypasscrypt.storage
-------------------

The module to manage password storage.

Classes:
--------
- `EPC`: The Encrypted Password Container (EPC) for operations on epc files.

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
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    '__copyright__',
    '__status__'
]

from binascii import hexlify
import os
from datetime import datetime
from struct import (
    pack,
    unpack
)
from typing import (
    Any,
    Callable,
    Dict,
    Optional,
    Tuple,
    List,
    Union
)
from pypasscrypt.cryptohandler import (
    SymmetricEncryptionTypes,
    SymmetricCryptoHandler,
    Hashing
)


class EPC:
    """
    pypasscrypt.storage.EPC
    ------------------------

    The Encrypted Password Container (EPC) class to manage password storage.

    Methods:
    --------
    - `load()`: Load the current commit data from the EPC object.
    - `save()`: Save the new commit to the EPC object.
    - `load_commit()`: Get the data for a specific commit hash.
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
    - `import_data()`: Import data to the storage.
    - `export_data()`: Export data from the storage.
    - `create()`: Create a new EPC object.
    - `verify()`: Verify the EPC file against provided details.

    Decorators:
    -----------
    - `@refresh`: Decorator to refresh the storage.
    - `@commit`: Decorator to commit changes to the storage.

    Attributes:
    -----------
    - `FILE_VERSION`: The file version of the EPC object.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    FILE_VERSION: str = "EPCv1.0"
    """
    pypasscrypt.storage.EPC.FILE_VERSION
    -----------------------------------

    The file version of the EPC object.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def load(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes
    ) -> Dict[str, Dict[str, str]]:
        """
        pypasscrypt.storage.EPC.load
        -----------------------------

        Load the current commit data from the EPC object.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :return: Dict[str, Dict[str, str]]

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not EPC.verify(
                file_path=file_path,
                secret=secret,
                symmetric_encryption_type=symmetric_encryption_type
        ):
            raise ValueError("Invalid file")

        with open(file_path, 'rb+') as file:
            file.seek(32 * 3)  # Skip the first 3 hashes
            current_commit_hash: bytes = file.read(32)

        # Get the data for the current commit hash
        data: Tuple[str, Dict[str, Dict[str, str]]] = EPC.load_commit(
            file_path=file_path,
            secret=secret,
            symmetric_encryption_type=symmetric_encryption_type,
            commit_hash=current_commit_hash
        )

        return data[1]

    @staticmethod
    def save(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            commit_data: Dict[str, Dict[str, str]],
            commit_message: str
    ) -> None:
        """
        pypasscrypt.storage.EPC.save
        -----------------------------

        Save the new commit to the EPC object.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :param commit_data: The data to commit.
        :param commit_message: The commit message.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not EPC.verify(
                file_path=file_path,
                secret=secret,
                symmetric_encryption_type=symmetric_encryption_type
        ):
            raise ValueError("Invalid file")

        temp_file_path: str = f"{file_path}.tmp"
        with open(file_path, 'rb+') as epc_file, open(temp_file_path, 'wb+') as tmp_file:
            epc_file.seek(32 * 4)  # Skip the first 4 hashes

            # Write the file version hash
            tmp_file.write(
                Hashing.generate_hash(
                    raw_str=EPC.FILE_VERSION
                )
            )

            # Write the password hash
            tmp_file.write(
                Hashing.generate_hash(
                    raw_str=secret
                )
            )

            # Write the encryption type hash
            tmp_file.write(
                Hashing.generate_hash(
                    raw_str=symmetric_encryption_type
                )
            )

            # create a new commit hash
            new_commit_hash: bytes = Hashing.generate_hash(
                raw_str=datetime.now().isoformat()
            )

            # encrypt the message
            encrypted_message: bytes = SymmetricCryptoHandler.encrypt(
                data=commit_message,
                password=secret,
                method=symmetric_encryption_type
            )

            # encrypt the data
            encrypted_data: bytes = SymmetricCryptoHandler.encrypt(
                data=commit_data,
                password=secret,
                method=symmetric_encryption_type
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

            # Replace the old file with the new file
        os.replace(temp_file_path, file_path)

    @staticmethod
    def load_commit(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            commit_hash: bytes
    ) -> Tuple[str, Dict[str, Dict[str, str]]]:
        """
        pypasscrypt.storage.EPC.load_commit
        -----------------------------------

        Get the commit message and data for a specific commit hash.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :param commit_hash: The commit hash to get data for.
        :return: Tuple[str, Dict[str, Dict[str, str]]]

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not EPC.verify(
                file_path=file_path,
                secret=secret,
                symmetric_encryption_type=symmetric_encryption_type
        ):
            raise ValueError("Invalid file")

        with open(file_path, 'rb+') as file:
            # Skip the first 4 hashes
            file.seek(32 * 4)

            commit_data: Optional[Dict[str, Dict[str, str]]] = None

            while not commit_data:
                # Read the current commit hash
                current_commit_hash: bytes = file.read(32)

                # Check if the commit hash is valid
                if not current_commit_hash:
                    raise ValueError("Invalid commit hash")

                # Read the commit message
                commit_message_length: int = unpack('I', file.read(4))[0]
                commit_message_bytes: bytes = file.read(
                    commit_message_length)

                # Read the commit data
                commit_data_length: int = unpack('I', file.read(4))[0]

                if current_commit_hash != commit_hash:
                    file.seek(commit_data_length, 1)
                    continue

                # Decrypt the commit data
                decrypted_message: Union[Dict[str, Dict[str, str]], str] = SymmetricCryptoHandler.decrypt(
                    encrypted_data=commit_message_bytes,
                    password=secret,
                    method=symmetric_encryption_type
                )

                # Check if the commit message is valid
                if isinstance(decrypted_message, str):
                    commit_message = decrypted_message
                else:
                    raise ValueError("Invalid commit message")

                # Decrypt the commit data
                decrypted_data: Union[Dict[str, Dict[str, str]], str] = SymmetricCryptoHandler.decrypt(
                    encrypted_data=file.read(commit_data_length),
                    password=secret,
                    method=symmetric_encryption_type
                )

                # Check if the commit data is valid
                if isinstance(decrypted_data, dict):
                    commit_data = decrypted_data
                else:
                    raise ValueError("Invalid commit data")

        return commit_message, commit_data

    @staticmethod
    def revert_to_commit(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            commit_hash: bytes
    ) -> None:
        """
        pypasscrypt.storage.EPC.revert_to_commit
        ----------------------------------------

        Revert the storage to a specific commit hash.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :param commit_hash: The commit hash to revert to.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not EPC.verify(
                file_path=file_path,
                secret=secret,
                symmetric_encryption_type=symmetric_encryption_type
        ):
            raise ValueError("Invalid file")
        temp_file_path: str = f"{file_path}.tmp"
        with open(file_path, 'rb+') as epc_file, open(temp_file_path, 'wb+') as tmp_file:
            tmp_file.write(epc_file.read(32 * 3))  # Copy the first 3 hashes

            tmp_file.write(commit_hash)  # Write the current commit hash

            epc_file.seek(32)  # Skip the current commit hash
            tmp_file.write(epc_file.read())

        # Replace the old file with the new file
        os.replace(temp_file_path, file_path)

    @staticmethod
    def change_secret(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            new_secret: str
    ) -> None:
        """
        pypasscrypt.storage.EPC.change_secret
        -------------------------------------

        Change the secret to encrypt/decrypt the passwords.

        :param file_path: The file path to manage password storage.
        :param secret: The current password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :param new_secret: The new password to encrypt/decrypt the passwords.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if not EPC.verify(
                file_path=file_path,
                secret=secret,
                symmetric_encryption_type=symmetric_encryption_type
        ):
            raise ValueError("Invalid file")

        # Create a temporary file
        temp_file_path: str = f"{file_path}.tmp"

        # Write the new secret to the file
        with open(file_path, 'rb+') as epc_file, open(temp_file_path, 'wb+') as tmp_file:

            # seek to the first commit hash
            epc_file.seek(0)
            tmp_file.seek(0)

            # Copy the first hash
            tmp_file.write(epc_file.read(32))

            # Write the new secret hash
            tmp_file.write(
                Hashing.generate_hash(raw_str=new_secret))

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
                    password=secret,
                    method=symmetric_encryption_type
                )

                if not isinstance(decrypted_message, str):
                    raise ValueError("Invalid commit message")

                # Encrypt the commit message with the new secret
                encrypted_message: bytes = SymmetricCryptoHandler.encrypt(
                    data=decrypted_message,
                    password=new_secret,
                    method=symmetric_encryption_type
                )

                # Read the commit data
                commit_data_length: int = unpack('I', epc_file.read(4))[0]
                commit_data: bytes = epc_file.read(commit_data_length)

                # Decrypt the commit data
                decrypted_data: Union[Dict[str, Dict[str, str]], str] = SymmetricCryptoHandler.decrypt(
                    encrypted_data=commit_data,
                    password=secret,
                    method=symmetric_encryption_type
                )

                if not isinstance(decrypted_data, dict):
                    raise ValueError("Invalid commit data")

                # Encrypt the commit data with the new secret
                encrypted_data: bytes = SymmetricCryptoHandler.encrypt(
                    data=decrypted_data,
                    password=new_secret,
                    method=symmetric_encryption_type
                )

                # Write the new commit to the file
                tmp_file.write(commit_hash)
                tmp_file.write(pack('I', len(encrypted_message)))
                tmp_file.write(encrypted_message)
                tmp_file.write(pack('I', len(encrypted_data)))
                tmp_file.write(encrypted_data)

        # Replace the old file with the new file
        os.replace(temp_file_path, file_path)

    @staticmethod
    def change_encryption_type(
            *,
            file_path: str,
            secret: str,
            current_symmetric_encryption_type: SymmetricEncryptionTypes,
            new_symmetric_encryption_type: SymmetricEncryptionTypes
    ) -> None:
        """
        pypasscrypt.storage.EPC.change_encryption_type
        ----------------------------------------------

        Change the encryption type.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param current_symmetric_encryption_type: The current encryption method to use.
        :param new_symmetric_encryption_type: The new encryption method to use.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not EPC.verify(
                file_path=file_path,
                secret=secret,
                symmetric_encryption_type=current_symmetric_encryption_type
        ):
            raise ValueError("Invalid file")

        # Create a temporary file
        temp_file_path: str = f"{file_path}.tmp"

        # Write the new encryption type to the file
        with open(file_path, 'rb+') as epc_file, open(temp_file_path, 'wb+') as tmp_file:

            # seek to the first commit hash
            epc_file.seek(0)
            tmp_file.seek(0)

            # Copy the first 2 hashes
            tmp_file.write(epc_file.read(32 * 2))

            # Write the new encryption type hash
            tmp_file.write(Hashing.generate_hash(
                raw_str=new_symmetric_encryption_type))

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
                    password=secret,
                    method=current_symmetric_encryption_type
                )

                if not isinstance(decrypted_message, str):
                    raise ValueError("Invalid commit message")

                # Encrypt the commit message with the new encryption type
                encrypted_message: bytes = SymmetricCryptoHandler.encrypt(
                    data=decrypted_message,
                    password=secret,
                    method=new_symmetric_encryption_type
                )

                # Read the commit data
                commit_data_length: int = unpack('I', epc_file.read(4))[0]
                commit_data: bytes = epc_file.read(commit_data_length)

                # Decrypt the commit data
                decrypted_data: Union[Dict[str, Dict[str, str]], str] = SymmetricCryptoHandler.decrypt(
                    encrypted_data=commit_data,
                    password=secret,
                    method=current_symmetric_encryption_type
                )

                if not isinstance(decrypted_data, dict):
                    raise ValueError("Invalid commit data")

                # Encrypt the commit data with the new encryption type
                encrypted_data = SymmetricCryptoHandler.encrypt(
                    data=decrypted_data,
                    password=secret,
                    method=new_symmetric_encryption_type
                )

                # Write the new commit to the file
                tmp_file.write(commit_hash)
                tmp_file.write(pack('I', len(encrypted_message)))
                tmp_file.write(encrypted_message)
                tmp_file.write(pack('I', len(encrypted_data)))
                tmp_file.write(encrypted_data)

        # Replace the old file with the new file
        os.replace(temp_file_path, file_path)

    @staticmethod
    def refresh(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        pypasscrypt.storage.EPC.refresh
        --------------------------------

        Decorator to refresh the storage.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :return: Callable

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            """
            pypasscrypt.storage.EPC.refresh.<decorator>
            ----------------------------------------

            Decorator to refresh the storage.

            :param func: The function to decorate.
            :return: Callable

            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """

            def wrapper(*args, **kwargs) -> None:
                """
                pypasscrypt.storage.EPC.refresh.<decorator>.<wrapper>
                --------------------------------------

                Wrapper function to refresh the storage.

                :param args: The arguments to the function.
                :param kwargs: The keyword arguments to the function.
                :return: None

                Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
                """
                # loads the current commit data

                return func(
                    *args,
                    **kwargs,
                    initial_data=EPC.load(
                        file_path=file_path,
                        secret=secret,
                        symmetric_encryption_type=symmetric_encryption_type
                    ),
                )

            return wrapper

        return decorator

    @staticmethod
    def commit(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes
    ) -> Callable[[Callable[..., Tuple[Dict[str, Dict[str, str]], str]]], Callable[..., None]]:
        """
        pypasscrypt.storage.EPC.commit
        -------------------------------

        Decorator to commit changes to the storage.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :return: Callable

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        def decorator(
                func: Callable[..., Tuple[Dict[str, Dict[str, str]], str]]
        ) -> Callable[..., None]:
            """
            pypasscrypt.storage.EPC.commit.<decorator>
            ---------------------------------------

            Decorator to commit changes to the storage.

            :param func: The function to decorate.
            :return: Callable

            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """

            @EPC.refresh(file_path=file_path, secret=secret, symmetric_encryption_type=symmetric_encryption_type)
            def wrapper(*args, **kwargs) -> None:
                """
                pypasscrypt.storage.EPC.commit.<decorator>.<wrapper>
                --------------------------------------

                Wrapper function to commit changes to the storage.

                :param args: The arguments to the function.
                :param kwargs: The keyword arguments to the function.
                :return: None

                Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
                """

                # Get the commit data
                commit_info: Tuple[Dict[str, Dict[str, str]],
                                   str] = func(*args, **kwargs)

                # Save the commit
                EPC.save(
                    file_path=file_path,
                    secret=secret,
                    symmetric_encryption_type=symmetric_encryption_type,
                    commit_data=commit_info[0],
                    commit_message=commit_info[1]
                )

            return wrapper

        return decorator

    @staticmethod
    def get_all_sites(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes
    ) -> List[str]:
        """
        pypasscrypt.storage.EPC.get_all_sites
        --------------------------------

        Get all the sites stored in the storage.

        :return: List[str]

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        @EPC.refresh(file_path=file_path, secret=secret, symmetric_encryption_type=symmetric_encryption_type)
        def __get_all_sites(initial_data: Dict[str, Dict[str, str]]) -> List[str]:
            """
            pypasscrypt.storage.EPC.get_all_sites.__get_all_sites
            --------------------------------

            Get all the sites stored in the storage.

            :return: List[str]

            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """

            return list(initial_data.keys())

        return __get_all_sites()

    @staticmethod
    def get_listings(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes
    ) -> List[Tuple[str, str]]:
        """
        pypasscrypt.storage.EPC.get_listings
        --------------------------------

        Get all the sites and usernames stored in the storage.

        :return: List[Tuple[str, str]]

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        @EPC.refresh(file_path=file_path, secret=secret, symmetric_encryption_type=symmetric_encryption_type)
        def __get_listings(initial_data: Dict[str, Dict[str, str]]) -> List[Tuple[str, str]]:
            """
            pypasscrypt.storage.EPC.get_listings.__get_listings
            --------------------------------
            Get all the sites and usernames stored in the storage.

            :return: List[Tuple[str, str]]

            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """
            return [(site, username) for site in initial_data for username in initial_data[site]]

        return __get_listings()

    @staticmethod
    def is_site_exists(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            site: str
    ) -> bool:
        """
        pypasscrypt.storage.EPC.is_site_exists
        --------------------------------

        Check if a site exists in the storage.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :param site: The site to check.
        :return: bool

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        @EPC.refresh(file_path=file_path, secret=secret, symmetric_encryption_type=symmetric_encryption_type)
        def __is_site_exists(_site: str, initial_data: Dict[str, Dict[str, str]]) -> bool:
            """
            pypasscrypt.storage.EPC.is_site_exists.__is_site_exists
            --------------------------------

            Check if a site exists in the storage.

            :param _site: The site to check.
            :param initial_data: The initial data.
            :return: bool

            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """
            return _site in initial_data

        return __is_site_exists(_site=site)

    @staticmethod
    def get_usernames(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            site: str
    ) -> List[str]:
        """
        pypasscrypt.storage.EPC.get_usernames
        --------------------------------

        Get the usernames for a specific site.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :param site: The site to get data for.
        :return: List[str]

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        @EPC.refresh(file_path=file_path, secret=secret, symmetric_encryption_type=symmetric_encryption_type)
        def __get_usernames(_site: str, initial_data: Dict[str, Dict[str, str]]) -> List[str]:
            """
            pypasscrypt.storage.EPC.get_usernames.__get_usernames
            --------------------------------

            Get the usernames for a specific site.

            :param _site: The site to get data for.
            :param initial_data: The initial data.
            :return: List[str]

            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """
            return list(initial_data[_site].keys())

        return __get_usernames(_site=site)

    @staticmethod
    def is_username_exists(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            site: str,
            username: str
    ) -> bool:
        """
        pypasscrypt.storage.EPC.is_username_exists
        --------------------------------

        Check if a username exists for a site.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :param site: The site to check.
        :param username: The username to check.
        :return: bool

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        @EPC.refresh(file_path=file_path, secret=secret, symmetric_encryption_type=symmetric_encryption_type)
        def __is_username_exists(_site: str, _username: str, initial_data: Dict[str, Dict[str, str]]) -> bool:
            """
            pypasscrypt.storage.EPC.is_username_exists.__is_username_exists
            --------------------------------

            Check if a username exists for a site.

            :param _site: The site to check.
            :param _username: The username to check.
            :return: bool

            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """
            return _username in initial_data.get(_site, {})

        return __is_username_exists(_site=site, _username=username)

    @staticmethod
    def add_password(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            site: str,
            username: str,
            password: str
    ) -> None:
        """
        pypasscrypt.storage.EPC.add_password
        --------------------------------

        Add a password to the storage.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :param site: The site to add password for.
        :param username: The username to add password for.
        :param password: The password to add.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        @EPC.commit(file_path=file_path, secret=secret, symmetric_encryption_type=symmetric_encryption_type)
        def __add_password(
                _site: str,
                _username: str,
                _password: str,
                initial_data: Dict[str, Dict[str, str]]
        ) -> Tuple[Dict[str, Dict[str, str]], str]:
            """
            pypasscrypt.storage.EPC.add_password.__add_password
            --------------------------------

            Add a password to the storage.

            :param _site: The site to add password for.
            :param _username: The username to add password for.
            :param _password: The password to add.
            :return: Tuple[Dict[str, Dict[str, str]], str]

            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """
            if _site not in initial_data:
                initial_data[_site] = {}

            initial_data[_site][_username] = _password
            return initial_data, f"Added password for {_username} at {_site}"

        return __add_password(_site=site, _username=username, _password=password)

    @staticmethod
    def get_password(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            site: str,
            username: str
    ) -> str:
        """
        pypasscrypt.storage.EPC.get_password
        --------------------------------

        Get the password for a site and username.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :param site: The site to get password for.
        :param username: The username to get password for.
        :return: str

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        @EPC.refresh(file_path=file_path, secret=secret, symmetric_encryption_type=symmetric_encryption_type)
        def __get_password(_site: str, _username: str, initial_data: Dict[str, Dict[str, str]]) -> str:
            """
            pypasscrypt.storage.EPC.get_password.__get_password
            --------------------------------

            Get the password for a site and username.

            :param _site: The site to get password for.
            :param _username: The username to get password for.
            :return: str

            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """
            return initial_data.get(_site, {}).get(_username, "")

        return __get_password(_site=site, _username=username)

    @staticmethod
    def edit_password(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            site: str,
            username: str,
            password: str
    ) -> None:
        """
        pypasscrypt.storage.EPC.edit_password
        --------------------------------

        Edit a password in the storage.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :param site: The site to edit password for.
        :param username: The username to edit password for.
        :param password: The password to edit.
        :return: None
        :raises ValueError: If site or username not found in the storage.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        @EPC.commit(file_path=file_path, secret=secret, symmetric_encryption_type=symmetric_encryption_type)
        def __edit_password(
                _site: str,
                _username: str,
                _password: str,
                initial_data: Dict[str, Dict[str, str]]
        ) -> Tuple[Dict[str, Dict[str, str]], str]:
            """
            pypasscrypt.storage.EPC.edit_password.__edit_password
            --------------------------------

            Edit a password in the storage.

            :param _site: The site to edit password for.
            :param _username: The username to edit password for.
            :param _password: The password to edit.
            :return: Tuple[Dict[str, Dict[str, str]], str]
            :raises ValueError: If site or username not found in the storage.

            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """
            if _site not in initial_data:
                raise ValueError(f"Site not found: {_site}")

            if _username not in initial_data[_site]:
                raise ValueError(f"Username not found: {_username}")

            initial_data[_site][_username] = _password
            return initial_data, f"Edited password for {_username} at {_site}"

        return __edit_password(_site=site, _username=username, _password=password)

    @staticmethod
    def remove_password(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            site: str,
            username: str
    ) -> None:
        """
        pypasscrypt.storage.EPC.remove_password
        --------------------------------

        Remove a password from the storage.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :param site: The site to remove password from.
        :param username: The username to remove password from.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        @EPC.commit(file_path=file_path, secret=secret, symmetric_encryption_type=symmetric_encryption_type)
        def __remove_password(
                _site: str,
                _username: str,
                initial_data: Dict[str, Dict[str, str]]
        ) -> Tuple[Dict[str, Dict[str, str]], str]:
            """
            pypasscrypt.storage.EPC.remove_password.__remove_password
            --------------------------------

            Remove a password from the storage.

            :param _site: The site to remove password from.
            :param _username: The username to remove password from.
            :return: Tuple[Dict[str, Dict[str, str]], str]

            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """
            if _site not in initial_data:
                raise ValueError(f"_Site not found: {_site}")

            if _username not in initial_data[_site]:
                raise ValueError(f"Username not found: {_username}")

            del initial_data[_site][_username]

            if len(initial_data[_site]) == 0:
                del initial_data[_site]

            return initial_data, f"Removed password for {_username} at {_site}"

        return __remove_password(_site=site, _username=username)

    @staticmethod
    def import_data(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            new_data: Dict[str, Dict[str, str]]
    ) -> None:
        """
        pypasscrypt.storage.EPC.import_data
        --------------------------------

        Import data to the storage.

        :param file_path: The file path to import data from.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :param new_data: The new data to import.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        @EPC.commit(file_path=file_path, secret=secret, symmetric_encryption_type=symmetric_encryption_type)
        def __import_data(
                _new_data: Dict[str, Dict[str, str]],
                initial_data: Dict[str, Dict[str, str]]
        ) -> Tuple[Dict[str, Dict[str, str]], str]:
            """
            pypasscrypt.storage.EPC.import_data.__import_data
            --------------------------------

            Import data to the storage.

            :param _new_data: The new data to import.
            :return: Tuple[Dict[str, Dict[str, str]], str]

            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """

            for site in _new_data:
                if site not in initial_data:
                    initial_data[site] = {}

                for username in new_data[site]:
                    initial_data[site][username] = new_data[site][username]

            return initial_data, "Imported data"

        return __import_data(_new_data=new_data)

    @staticmethod
    def export_data(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            listings: List[Tuple[str, str]]
    ) -> Dict[str, Dict[str, str]]:
        """
        pypasscrypt.storage.EPC.export_data
        --------------------------------

        Export data from the storage.

        :param file_path: The file path to export data to.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :param listings: The listings to export.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        @EPC.refresh(file_path=file_path, secret=secret, symmetric_encryption_type=symmetric_encryption_type)
        def __export_data(
                _listings: List[Tuple[str, str]],
                initial_data: Dict[str, Dict[str, str]]
        ) -> Dict[str, Dict[str, str]]:
            """
            pypasscrypt.storage.EPC.export_data.__export_data
            --------------------------------

            Export data from the storage.

            :param _listings: The listings to export.
            :param initial_data: The initial data.
            :return: Dict[str, Dict[str, str]]

            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """
            export_data: Dict[str, Dict[str, str]] = {}
            for site, username in _listings:
                if site not in export_data:
                    export_data[site] = {}

                export_data[site][username] = initial_data[site][username]

            return export_data

        return __export_data(_listings=listings)

    @staticmethod
    def create(
            *,
            directory: str,
            file_name: str,
            extension: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes,
            initial_data: Optional[Dict[str, Dict[str, str]]] = None
    ) -> str:
        """
        pypasscrypt.storage.EPC.create
        -------------------------------

        Create a new EPC object.

        :param directory: The directory to store the EPC file.
        :param file_name: The name of the EPC file.
        :param extension: The extension of the EPC file.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :param initial_data: The initial data to store.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        file_hash = hexlify(Hashing.generate_hash(
            raw_str=datetime.now().isoformat())).decode('utf-8')
        file_name = f"{file_name}_{file_hash}.{extension}"
        file_path = os.path.join(directory, file_name)
        os.makedirs(directory, exist_ok=True)

        with open(file_path, 'wb+') as file:
            file.seek(0)

            # Write file version (32 bytes)
            file.write(Hashing.generate_hash(
                raw_str=EPC.FILE_VERSION
            ))

            # Write password hash (32 bytes)
            file.write(Hashing.generate_hash(
                raw_str=secret
            ))

            # Write encryption type hash (32 bytes)
            file.write(Hashing.generate_hash(
                raw_str=symmetric_encryption_type
            ))

            current_commit_info = datetime.now().isoformat()

            # write current commit hash (32 bytes)
            file.write(Hashing.generate_hash(
                raw_str=current_commit_info
            ))

            # create a new commit hash (32 bytes)
            file.write(Hashing.generate_hash(
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

            # encrypt the data
            if not initial_data:
                initial_data = {}

            encrypted_data = SymmetricCryptoHandler.encrypt(
                data=initial_data,
                password=secret,
                method=symmetric_encryption_type
            )

            # Write data length (4 bytes)
            file.write(pack('I', len(encrypted_data)))

            # Write data (n bytes)
            file.write(encrypted_data)

        return file_path

    @staticmethod
    def verify(
            *,
            file_path: str,
            secret: str,
            symmetric_encryption_type: SymmetricEncryptionTypes
    ) -> bool:
        """
        pypasscrypt.storage.EPC.verify
        -------------------------------

        Verify the EPC file against provided details.

        :param file_path: The file path to manage password storage.
        :param secret: The password to encrypt/decrypt the passwords.
        :param symmetric_encryption_type: The encryption method to use.
        :return: bool   

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not os.path.exists(file_path):
            return False

        try:
            with open(file_path, 'rb+') as file:
                file.seek(0)

                # Verify file version (32 bytes)
                if not Hashing.verify_hash(
                        raw_str=EPC.FILE_VERSION,
                        hash_bytes=file.read(32)
                ):
                    return False

                # Verify file hash (32 bytes)
                elif not Hashing.verify_hash(
                        raw_str=secret,
                        hash_bytes=file.read(32)
                ):
                    return False

                # Verify encryption type (32 bytes)
                elif not Hashing.verify_hash(
                        raw_str=symmetric_encryption_type,
                        hash_bytes=file.read(32)
                ):
                    return False

                return True
        except ValueError:
            return False
