"""
pypasscrypt.config
------------------

A class for the PassCrypt configuration.

Model classes:
----------------
- `ImmutableConfig`: A class for immutable configuration.
- `MutableConfig`: A class for mutable configuration.
- `BaseConfig`: A class for base configuration.

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
    'BaseConfig',
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    '__status__'
]

import os
import json
from pathlib import Path
from pydantic import (
    BaseModel,
    Field,
    ValidationError
)
from typing import (
    Dict,
    List,
    Literal,
    Union,
    get_args
)
from socket import (
    gethostbyname,
    gethostname
)


class ImmutableConfig(BaseModel):
    """
    pypasscrypt.config.ImmutableConfig
    ---------------------------------

    A class for immutable configuration.

    Attributes:
    ----------------
    - `IP`: str: The IP address of the host.
    - `STORAGE_DIRECTORY`: str: The directory for storage files.
    - `STORAGE_FILE_NAME`: str: The filename for storage files.
    - `STORAGE_EXTENSION`: str: The file extension for storage files.
    - `EXPORT_DIRECTORY`: str: The directory for export files.
    - `EXPORT_FILE_NAME`: str: The filename for export files.
    - `APPLICATION_NAME`: str: The application name.
    - `LOG_STRUCTURE`: str: The log structure.
    - `LOG_LEVEL`: str: The log level.
    - `SIMILAR_CHARACTERS`: Dict[str, str]: The similar character's dictionary.
    - `CONTEXT_FILTERS`: List[str]: The context filters list.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    APPLICATION_NAME: str = "PassCrypt"
    """
    pypasscrypt.config.ImmutableConfig.APPLICATION_NAME
    --------------------------------------------------

    The application name.
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    STORAGE_DIRECTORY: str = Field(default_factory=lambda: os.path.join(
        os.getenv("PROGRAMDATA", ""), "passcrypt"))
    """
    pypasscrypt.config.ImmutableConfig.STORAGE_DIRECTORY
    ---------------------------------------------------

    The directory for storage files.
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    STORAGE_FILE_NAME: str = Field(default_factory=lambda: "passcrypt_storage")
    """
    pypasscrypt.config.ImmutableConfig.STORAGE_FILE_NAME
    ---------------------------------------------------

    The filename for storage files.
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    STORAGE_EXTENSION: str = "epc"
    """
    pypasscrypt.config.ImmutableConfig.STORAGE_EXTENSION
    ---------------------------------------------------

    The file extension for storage files.
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    EXPORT_DIRECTORY: str = Field(default_factory=lambda: os.path.join(
        Path.home(), "Downloads", "passcrypt_exports"))
    """
    pypasscrypt.config.ImmutableConfig.EXPORT_DIRECTORY
    ---------------------------------------------------

    The directory for export files.
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    EXPORT_FILE_NAME: str = Field(default_factory=lambda: "passcrypt_export")
    """
    pypasscrypt.config.ImmutableConfig.EXPORT_FILE_NAME
    ---------------------------------------------------

    The filename for export files.
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    LOG_STRUCTURE: str = "%(asctime)s - %(levelname)s - %(message)s"
    """
    pypasscrypt.config.ImmutableConfig.LOG_STRUCTURE
    ------------------------------------------------

    The log structure.
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    LOG_LEVEL: int = 20
    """
    pypasscrypt.config.ImmutableConfig.LOG_LEVEL
    --------------------------------------------

    The log level.
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    IP: str = Field(default_factory=lambda: gethostbyname(gethostname()))
    """
    pypasscrypt.config.ImmutableConfig.IP
    --------------------------------

    The IP address of the host.
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    SIMILAR_CHARACTERS: Dict[str, str] = {
        "o": "0",
        "0": "o",
        "s": "5",
        "S": "5",
        "5": "s",
        "B": "8",
        "8": "B",
        "Z": "2",
        "z": "2",
        "2": "Z",
        "q": "9",
        "9": "q",
        "1": "l",
        "l": "1",
        "i": "1",
        "3": "E",
        "E": "3",
        "A": "4",
        "4": "A",
        "T": "7",
        "7": "T",
        "G": "6",
        "6": "G",
        "g": "9"
    }
    """
    pypasscrypt.config.ImmutableConfig.SIMILAR_CHARACTERS
    ---------------------------------------------------

    The similar characters dictionary.
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    CONTEXT_FILTERS: List[str] = [
        "gmail",
        "email",
        "com",
        "in",
        "co",
        "uk",
        "outlook",
        "onedrive",
        "yahoo",
        "google",
        "test",
        "password",
        "admin",
        "user",
        "login",
        "secure",
        "key",
        "root",
        "123456",
        "qwerty",
        "abc123",
        "password123",
        "letmein",
        "welcome",
        "admin123",
        "123456789",
        "12345678",
        "12345",
        "1234567",
        "1234567890",
        "password1",
        "1234",
        "password1234",
        "password12",
        "password12345",
        "password123456",
        "password1234567",
        "password12345678",
        "password123456789",
        "password1234567890",
        "default",
        "admin1",
        "admin2",
        "user1",
        "user2",
        "welcome1",
        "test123",
        "guest",
        "guest1",
        "guest123",
        "changeme",
        "changeme123",
        "root123",
        "rootpass",
        "system",
        "sysadmin",
        "superuser",
        "administrator",
        "manager",
        "testuser",
        "public",
        "demo",
        "example",
        "temp",
        "temp123",
        "tempuser",
        "publicuser",
        "public123",
        "trial",
        "trial123"
    ]
    """
    pypasscrypt.config.ImmutableConfig.CONTEXT_FILTERS
    --------------------------------------------------

    The context filters list.
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    class Config:
        frozen = True


class MutableConfig(BaseModel):
    """
    pypasscrypt.config.MutableConfig
    --------------------------------

    A class for mutable configuration.

    Attributes:
    ------------
    - `DEFAULT_PORT`: int: The default port.
    - `ASYMMETRIC_ENCRYPTION_TYPE`: AsymmetricEncryptionMethod: The asymmetric encryption type.
    - `SYMMETRIC_ENCRYPTION_TYPE`: SymmetricEncryptionMethod: The symmetric encryption type.
    - `PASSWORD_LENGTH`: int: The password length.
    - `UPPER_CASE_ALLOWED`: bool: The upper case allowed flag.
    - `LOWER_CASE_ALLOWED`: bool: The lower case allowed flag.
    - `DIGITS_ALLOWED`: bool: The digits allowed flag.
    - `SYMBOLS_ALLOWED`: bool: The symbols allowed flag.
    - `SIMILAR_CHARACTERS_ALLOWED`: bool: The similar characters allowed flag.

    Methods:
    --------
    - `load()`: Load the configuration from a file.
    - `save()`: Save the configuration to a file.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    DEFAULT_PORT: int = 12345
    """
    pyppasscrypt.config.MutableConfig.DEFAULT_PORT
    -------------------------------------------

    The default port.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    ASYMMETRIC_ENCRYPTION_TYPE: AsymmetricEncryptionTypes = "RSA"
    """
    pyppasscrypt.config.MutableConfig.ASYMMETRIC_ENCRYPTION_TYPE
    -----------------------------------------------------------

    The asymmetric encryption type.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    SYMMETRIC_ENCRYPTION_TYPE: SymmetricEncryptionTypes = "AES"
    """
    pyppasscrypt.config.MutableConfig.SYMMETRIC_ENCRYPTION_TYPE
    ----------------------------------------------------------

    The symmetric encryption type.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    PASSWORD_LENGTH: int = 16
    """
    pyppasscrypt.config.MutableConfig.PASSWORD_LENGTH
    ------------------------------------------------
    
    The password length.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    UPPER_CASE_ALLOWED: bool = True
    """
    pyppasscrypt.config.MutableConfig.UPPER_CASE_ALLOWED
    ---------------------------------------------------

    The upper case allowed flag.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    LOWER_CASE_ALLOWED: bool = True
    """
    pyppasscrypt.config.MutableConfig.LOWER_CASE_ALLOWED
    ---------------------------------------------------

    The lower case allowed flag.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    DIGITS_ALLOWED: bool = True
    """
    pyppasscrypt.config.MutableConfig.DIGITS_ALLOWED
    ----------------------------------------------

    The digits allowed flag.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    SYMBOLS_ALLOWED: bool = True
    """
    pyppasscrypt.config.MutableConfig.SYMBOLS_ALLOWED
    -----------------------------------------------

    The symbols allowed flag.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    SIMILAR_CHARACTERS_ALLOWED: bool = True
    """
    pyppasscrypt.config.MutableConfig.SIMILAR_CHARACTERS_ALLOWED
    -----------------------------------------------------------

    The similar characters allowed flag.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    class Config:
        frozen = False

    def load(self, file_path: str) -> "MutableConfig":
        """
        pypasscrypt.config.MutableConfig.load
        -------------------------------------

        Load the configuration from a file.

        :param file_path: str: The file path.
        :return: MutableConfig: The mutable configuration

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)
            return self.model_validate(data)
        except (FileNotFoundError, ValidationError, json.JSONDecodeError):
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            self.save(file_path)
            return self

    def save(self, file_path: str) -> None:
        """
        pypasscrypt.config.MutableConfig.save
        -------------------------------------

        Save the configuration to a file.

        :param file_path: str: The file path.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        data = self.model_dump()
        with open(file_path, 'w') as file:
            json.dump(data, file, indent=4)


class BaseConfig(BaseModel):
    """
    pypasscrypt.config.BaseConfig
    ------------------------------

    A class for base configuration.

    Attributes:
    ------------
    - `base_file_path`: str: The base file path.
    - `immutable`: ImmutableConfig: The immutable configuration.
    - `mutable`: MutableConfig: The mutable configuration.

    Methods:
    --------
    - `set()`: Set the configuration field.
    - `get()`: Get the configuration field.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    base_file_path: str
    """
    pypasscrypt.config.BaseConfig.base_file_path
    -------------------------------------------

    The base file path.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    immutable: ImmutableConfig = ImmutableConfig()
    """
    pypasscrypt.config.BaseConfig.immutable
    --------------------------------------

    The immutable configuration.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    mutable: MutableConfig = MutableConfig()
    """
    pypasscrypt.config.BaseConfig.mutable
    ------------------------------------

    The mutable configuration.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def set(self, *, key: Literal[
        "DEFAULT_PORT",
        "ASYMMETRIC_ENCRYPTION_TYPE",
        "SYMMETRIC_ENCRYPTION_TYPE",
        "PASSWORD_LENGTH",
        "UPPER_CASE_ALLOWED",
        "LOWER_CASE_ALLOWED",
        "DIGITS_ALLOWED",
        "SYMBOLS_ALLOWED",
        "SIMILAR_CHARACTERS_ALLOWED"
    ], value: Union[int, AsymmetricEncryptionTypes, SymmetricEncryptionTypes, bool]) -> None:
        """
        pypasscrypt.config.BaseConfig.set
        ---------------------------------

        Set the configuration field.

        :param key: The key.
        :param value: The new value.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        integer_type = ["DEFAULT_PORT", "PASSWORD_LENGTH"]
        asymmetric_encryption_type = ["ASYMMETRIC_ENCRYPTION_TYPE"]
        symmetric_encryption_type = ["SYMMETRIC_ENCRYPTION_TYPE"]
        boolean_type = [
            "UPPER_CASE_ALLOWED",
            "LOWER_CASE_ALLOWED",
            "DIGITS_ALLOWED",
            "SYMBOLS_ALLOWED",
            "SIMILAR_CHARACTERS_ALLOWED"
        ]

        if key in integer_type:
            if not isinstance(value, int):
                raise ValueError(f"Value for {key} must be of type 'int'.")

        elif key in asymmetric_encryption_type:
            if value not in get_args(AsymmetricEncryptionTypes):
                raise ValueError(
                    f"Value for {key} must be of type 'AsymmetricEncryptionTypes'.")

        elif key in symmetric_encryption_type:
            if value not in get_args(SymmetricEncryptionTypes):
                raise ValueError(
                    f"Value for {key} must be of type 'SymmetricEncryptionTypes'.")

        elif key in boolean_type:
            if not isinstance(value, bool):
                raise ValueError(f"Value for {key} must be of type 'bool'.")

        else:
            raise ValueError(f"Field '{key}' not found in the configuration.")

        if key in self.mutable.model_fields:
            self.mutable = self.mutable.load(file_path=self.base_file_path)
            setattr(self.mutable, key, value)
            self.mutable.save(self.base_file_path)
        else:
            raise ValueError(
                f"Cannot update field '{key}' because it is immutable or not allowed.")

    def get(self, *, key: Literal[
        "IP",
        "STORAGE_DIRECTORY",
        "STORAGE_FILE_NAME",
        "STORAGE_EXTENSION",
        "EXPORT_DIRECTORY",
        "EXPORT_FILE_NAME",
        "APPLICATION_NAME",
        "LOG_STRUCTURE",
        "LOG_LEVEL",
        "SIMILAR_CHARACTERS",
        "CONTEXT_FILTERS",
        "DEFAULT_PORT",
        "ASYMMETRIC_ENCRYPTION_TYPE",
        "SYMMETRIC_ENCRYPTION_TYPE",
        "PASSWORD_LENGTH",
        "UPPER_CASE_ALLOWED",
        "LOWER_CASE_ALLOWED",
        "DIGITS_ALLOWED",
        "SYMBOLS_ALLOWED",
        "SIMILAR_CHARACTERS_ALLOWED"
    ]) -> Union[str, int, AsymmetricEncryptionTypes, SymmetricEncryptionTypes, bool, Dict[str, str], List[str]]:
        """
        pypasscrypt.config.BaseConfig.get
        --------------------------------

        Get the configuration field.

        :param key: The key.
        :return:  The value.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.mutable = self.mutable.load(file_path=self.base_file_path)
        if key in self.mutable.model_fields:
            return getattr(self.mutable, key)
        elif key in self.immutable.model_fields:
            return getattr(self.immutable, key)
        else:
            raise ValueError(f"Field '{key}' not found in the configuration.")


test = BaseConfig(base_file_path=os.path.join(os.path.dirname(__file__), "config.json"))    

print(test.get(key="DEFAULT_PORT"))