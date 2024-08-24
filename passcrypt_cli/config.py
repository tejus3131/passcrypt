from datetime import datetime
import os
import json
from pathlib import Path
from time import sleep
from pydantic import (
    BaseModel,
    Field
)
from typing import (
    Any,
    Dict,
    List,
    Literal,
    Optional,
    Union,
    get_args
)
from socket import (
    gethostbyname,
    gethostname
)
from pypasscrypt import (
    AsymmetricEncryptionTypes,
    HashHandler,
    InvalidAsymmetricEncryptionTypeError,
    HashTypes,
    InvalidHashTypeError,
    SymmetricEncryptionTypes,
    InvalidSymmetricEncryptionTypeError,
    EPC
)
from logging import (
    Logger,
    getLogger,
    FileHandler,
    Formatter,
    INFO
)

from pypasscrypt.connectionhandler import ConnectionProtocolTypes, InvalidConnectionProtocolError
from pypasscrypt.passwordhandler import PasswordManagerTypes, InvalidPasswordManagerTypeError


class ApplicationDetails(BaseModel):

    APPLICATION_NAME: str = "PassCrypt"

    STORAGE_DIRECTORY: str = Field(
        default_factory=lambda: os.path.join(os.getenv("PROGRAMDATA", "")))

    EXPORT_DIRECTORY: str = Field(
        default_factory=lambda: os.path.join(Path.home(), "Downloads"))

    CONFIG_FILE_EXTENSION: str = "json"

    STORAGE_FILE_EXTENSION: str = "epc"

    EXPORT_FILE_EXTENSION: str = "ept"

    LOG_FILE_EXTENSION: str = "log"

    LOG_STRUCTURE: str = "%(asctime)s - %(levelname)s - %(message)s"

    LOG_LEVEL: int = INFO

    IP: str = Field(default_factory=lambda: gethostbyname(gethostname()))

    CONFIG_VERSION: str = "CONFIGv1.0"

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

    def get(
            self,
            *,
            key: Literal[
                "APPLICATION_NAME",
                "CONFIG_FILE_NAME",
                "STORAGE_FILE_NAME",
                "EXPORT_FILE_NAME",
                "EXPORT_CONFIG_FILE_NAME",
                "LOG_FILE_NAME",
                "LOG_STRUCTURE",
                "LOG_LEVEL",
                "IP",
                "SIMILAR_CHARACTERS",
                "CONTEXT_FILTERS"
            ],
            userhash: Optional[str] = None
    ) -> Union[str, int, Dict[str, str], List[str]]:

        if not isinstance(key, str):
            raise TypeError("Key must be of type 'str'.")

        if key in ['APPLICATION_NAME', 'LOG_STRUCTURE', 'LOG_LEVEL', 'IP', 'SIMILAR_CHARACTERS', 'CONTEXT_FILTERS']:
            return getattr(self, key)

        if key == "CONFIG_FILE_NAME":
            return os.path.join(
                self.STORAGE_DIRECTORY,
                self.APPLICATION_NAME,
                f"{self.APPLICATION_NAME}.{self.CONFIG_FILE_EXTENSION}"
            )

        if not isinstance(userhash, str):
            raise TypeError("Userhash must be of type 'str'.")
        
        if not userhash:
            raise ValueError(f"userhash is required for: {key}")

        if key == "STORAGE_FILE_NAME":
            return os.path.join(
                self.STORAGE_DIRECTORY,
                self.APPLICATION_NAME,
                f"{self.APPLICATION_NAME.lower()}_storage_file_{userhash}.{self.STORAGE_FILE_EXTENSION}"
            )

        elif key == "EXPORT_FILE_NAME":
            return os.path.join(
                self.EXPORT_DIRECTORY,
                self.APPLICATION_NAME,
                f"{self.APPLICATION_NAME.lower()}_export_file_{userhash}.{self.EXPORT_FILE_EXTENSION}"
            )

        elif key == "LOG_FILE_NAME":
            return os.path.join(
                self.STORAGE_DIRECTORY,
                self.APPLICATION_NAME,
                f"{self.APPLICATION_NAME.lower()}_log_file_{userhash}.{self.LOG_FILE_EXTENSION}"
            )
        
        elif key == "EXPORT_CONFIG_FILE_NAME":
            return os.path.join(
                self.EXPORT_DIRECTORY,
                self.APPLICATION_NAME,
                f"{self.APPLICATION_NAME.lower()}_export_config_file_{userhash}.{self.CONFIG_FILE_EXTENSION}"
            )

        else:
            raise ValueError(f"Field '{key}' not found in the configuration.")

    class Config:
        frozen = True


class UserDetails(BaseModel):

    USERHASH: str = Field(default_factory=lambda: HashHandler.generate_hash(
        data=datetime.now().isoformat(),
        method="SHA256"
    ))

    DEFAULT_PORT: int = Field(default=12345, ge=0, le=65535)

    CONNECTION_PROTOCOL: ConnectionProtocolTypes = "PassCryptConnectionProtocolHandler"

    ASYMMETRIC_ENCRYPTION_TYPE: AsymmetricEncryptionTypes = "RSA"

    SYMMETRIC_ENCRYPTION_TYPE: SymmetricEncryptionTypes = "AES"

    HASH_TYPE: HashTypes = "SHA256"

    PASSWORD_MANAGER_TYPE: PasswordManagerTypes = "PassCryptPasswordManager"

    PASSWORD_LENGTH: int = Field(default=16, ge=0)

    UPPER_CASE_ALLOWED: bool = True

    LOWER_CASE_ALLOWED: bool = True

    DIGITS_ALLOWED: bool = True

    SYMBOLS_ALLOWED: bool = True

    SIMILAR_CHARACTERS_ALLOWED: bool = True

    class Config:
        frozen = False


class UserConfig(BaseModel):
    APPLICATION_NAME: str
    STORAGE_FILE_NAME: str
    EXPORT_FILE_NAME: str
    IP: str
    CONNECTION_PROTOCOL: ConnectionProtocolTypes
    SIMILAR_CHARACTERS: Dict[str, str]
    CONTEXT_FILTERS: List[str]
    DEFAULT_PORT: int
    ASYMMETRIC_ENCRYPTION_TYPE: AsymmetricEncryptionTypes
    SYMMETRIC_ENCRYPTION_TYPE: SymmetricEncryptionTypes
    HASH_TYPE: HashTypes
    PASSWORD_MANAGER_TYPE: PasswordManagerTypes
    PASSWORD_LENGTH: int
    UPPER_CASE_ALLOWED: bool
    LOWER_CASE_ALLOWED: bool
    DIGITS_ALLOWED: bool
    SYMBOLS_ALLOWED: bool
    SIMILAR_CHARACTERS_ALLOWED: bool
    IMPORT_FILE_PATH: str
    IMPORT_FILE_EXTENSION: str
    CONFIG_FILE_EXTENSION: str


class Config(BaseModel):

    application_details: ApplicationDetails = ApplicationDetails()
    users: Dict[str, UserDetails] = {}

    def load(self) -> None:
        file_path: Union[str, int, Dict[str, str], List[str]
                         ] = self.application_details.get(key="CONFIG_FILE_NAME")

        if not isinstance(file_path, str):
            raise TypeError("file_path must be string.")

        try:
            with open(file_path, "r") as file:
                data: Dict[str, dict] = json.load(file)
            for key in data:
                self.users[key] = UserDetails(**data[key])
        except FileNotFoundError:
            self.save()

    def save(self) -> None:
        file_path: Union[str, int, Dict[str, str], List[str]] = self.application_details.get(key="CONFIG_FILE_NAME")

        if not isinstance(file_path, str):
            raise TypeError("file_path must be string.")

        if not os.path.exists(os.path.dirname(file_path)):
            os.makedirs(os.path.dirname(file_path))

        data: Dict[str, Dict[str, Union[str, bool, int]]] = {}

        for key in self.users:
            data[key] = self.users[key].model_dump()

        with open(file_path, "w+") as file:
            json.dump(data, file, indent=4)

    def change_username(self, *, old_username: str, new_username: str) -> None:
        if not isinstance(old_username, str):
            raise TypeError("Old username must be of type 'str'.")

        if not isinstance(new_username, str):
            raise TypeError("New username must be of type 'str'.")

        self.load()

        if old_username not in self.users:
            raise ValueError(
                f"User '{old_username}' not found in the configuration.")

        if new_username in self.users:
            raise ValueError(
                f"User '{new_username}' already exists in the configuration.")

        self.users[new_username] = self.users.pop(old_username)
        self.save()

    def create(self, *, username: str, secret: str) -> None:
        if not isinstance(username, str):
            raise TypeError("Username must be of type 'str'.")
        
        if not isinstance(secret, str):
            raise TypeError("Secret must be of type 'str'.")
        
        self.load()

        if username in self.users:
            raise ValueError(
                f"User '{username}' already exists in the configuration.")

        self.users[username] = UserDetails()

        storage_file_path: Union[str, int, Dict[str, str], List[str]] = self.application_details.get(
            key="STORAGE_FILE_NAME", userhash=self.users[username].USERHASH)

        if not isinstance(storage_file_path, str):
            raise TypeError("storage_file_path must be string.")

        log_file_path: Union[str, int, Dict[str, str], List[str]] = self.application_details.get(
            key="LOG_FILE_NAME", userhash=self.users[username].USERHASH)

        if not isinstance(log_file_path, str):
            raise TypeError("log_file_path must be string.")

        EPC.create(
            secret=secret,
            symmetric_encryption_type=self.users[username].SYMMETRIC_ENCRYPTION_TYPE,
            hash_type=self.users[username].HASH_TYPE,
            file_path=storage_file_path
        )

        with open(log_file_path, "w+") as file:
            file.write(f"File created at {datetime.now().isoformat()}.")

        self.save()

    def read(
            self,
            *,
            username: str
    ) -> UserConfig:

        if not isinstance(username, str):
            raise TypeError("Username must be of type 'str'.")

        self.load()

        if username not in self.users:
            raise ValueError(
                f"User '{username}' not found in the configuration.")
        
        storage_file_name = self.application_details.get(
            key="STORAGE_FILE_NAME", userhash=self.users[username].USERHASH)
        
        export_file_name = self.application_details.get(
            key="EXPORT_FILE_NAME", userhash=self.users[username].USERHASH)
        
        
        return UserConfig(
            APPLICATION_NAME=self.application_details.APPLICATION_NAME,
            STORAGE_FILE_NAME=storage_file_name if isinstance(storage_file_name, str) else "",
            EXPORT_FILE_NAME=export_file_name if isinstance(export_file_name, str) else "",
            IP=self.application_details.IP,
            CONNECTION_PROTOCOL=self.users[username].CONNECTION_PROTOCOL,
            SIMILAR_CHARACTERS=self.application_details.SIMILAR_CHARACTERS,
            CONTEXT_FILTERS=self.application_details.CONTEXT_FILTERS,
            DEFAULT_PORT=self.users[username].DEFAULT_PORT,
            ASYMMETRIC_ENCRYPTION_TYPE=self.users[username].ASYMMETRIC_ENCRYPTION_TYPE,
            SYMMETRIC_ENCRYPTION_TYPE=self.users[username].SYMMETRIC_ENCRYPTION_TYPE,
            HASH_TYPE=self.users[username].HASH_TYPE,
            PASSWORD_MANAGER_TYPE=self.users[username].PASSWORD_MANAGER_TYPE,
            PASSWORD_LENGTH=self.users[username].PASSWORD_LENGTH,
            UPPER_CASE_ALLOWED=self.users[username].UPPER_CASE_ALLOWED,
            LOWER_CASE_ALLOWED=self.users[username].LOWER_CASE_ALLOWED,
            DIGITS_ALLOWED=self.users[username].DIGITS_ALLOWED,
            SYMBOLS_ALLOWED=self.users[username].SYMBOLS_ALLOWED,
            SIMILAR_CHARACTERS_ALLOWED=self.users[username].SIMILAR_CHARACTERS_ALLOWED,
            IMPORT_FILE_PATH=self.application_details.EXPORT_DIRECTORY,
            IMPORT_FILE_EXTENSION=self.application_details.EXPORT_FILE_EXTENSION,
            CONFIG_FILE_EXTENSION=self.application_details.CONFIG_FILE_EXTENSION
        )

    def update(
            self,
            *,
            key: Literal[
                "DEFAULT_PORT",  # connection
                "CONNECTION_PROTOCOL",  # connection
                "ASYMMETRIC_ENCRYPTION_TYPE",  # cryptography
                "SYMMETRIC_ENCRYPTION_TYPE",  # cryptography
                "HASH_TYPE",  # cryptography
                "PASSWORD_MANAGER_TYPE",  # password
                "PASSWORD_LENGTH",  # password
                "UPPER_CASE_ALLOWED",  # password
                "LOWER_CASE_ALLOWED",  # password
                "DIGITS_ALLOWED",  # password
                "SYMBOLS_ALLOWED",  # password
                "SIMILAR_CHARACTERS_ALLOWED"  # password
            ],
            value: Any,
            username: str
    ) -> None:
        integer_type = ["DEFAULT_PORT", "PASSWORD_LENGTH"]
        asymmetric_encryption_type = ["ASYMMETRIC_ENCRYPTION_TYPE"]
        symmetric_encryption_type = ["SYMMETRIC_ENCRYPTION_TYPE"]
        connection_protocol_type = ["CONNECTION_PROTOCOL"]
        password_manager_type = ["PASSWORD_MANAGER_TYPE"]
        hash_type = ["HASH_TYPE"]
        boolean_type = [
            "UPPER_CASE_ALLOWED",
            "LOWER_CASE_ALLOWED",
            "DIGITS_ALLOWED",
            "SYMBOLS_ALLOWED",
            "SIMILAR_CHARACTERS_ALLOWED"
        ]

        if not isinstance(username, str):
            raise TypeError("Username must be of type 'str'.")

        if username not in self.users:
            raise ValueError(
                f"User '{username}' not found in the configuration.")

        if key in integer_type:
            if not isinstance(value, int):
                raise TypeError(f"Value for {key} must be of type 'int'.")

        elif key in asymmetric_encryption_type:
            if value not in get_args(AsymmetricEncryptionTypes):
                raise InvalidAsymmetricEncryptionTypeError(
                    message=f"Invalid value for {key}.") from TypeError(value)

        elif key in symmetric_encryption_type:
            if value not in get_args(SymmetricEncryptionTypes):
                raise InvalidSymmetricEncryptionTypeError(
                    message=f"Invalid value for {key}.") from TypeError(value)

        elif key in hash_type:
            if value not in get_args(HashTypes):
                raise InvalidHashTypeError(
                    message=f"Invalid value for {key}.") from TypeError(value)

        elif key in boolean_type:
            if not isinstance(value, bool):
                raise TypeError(f"Value for {key} must be of type 'bool'.")
            
        elif key in connection_protocol_type:
            if value not in get_args(ConnectionProtocolTypes):
                raise InvalidConnectionProtocolError(
                    message=f"Invalid value for {key}.") from TypeError(value)
            
        elif key in password_manager_type:
            if value not in get_args(PasswordManagerTypes):
                raise InvalidPasswordManagerTypeError(
                    message=f"Invalid value for {key}.") from TypeError(value)

        else:
            raise ValueError(f"Field '{key}' not found in the configuration.")

        self.load()
        setattr(self.users[username], key, value)
        self.get_logger(username=username).info(
            f"Updated '{key}' to '{value}'.")
        self.save()

    def delete(self, *, username: str) -> None:
        if not isinstance(username, str):
            raise TypeError("Username must be of type 'str'.")

        if username not in self.users:
            raise ValueError(
                f"User '{username}' not found in the configuration.")
        
        self.load()

        storage_file_name: Union[str, int, Dict[str, str], List[str]] = self.application_details.get(
            key="STORAGE_FILE_NAME", userhash=self.users[username].USERHASH)
        
        if not isinstance(storage_file_name, str):
            raise TypeError("Invalid storage_file_name")
        
        if os.path.exists(storage_file_name):
            os.remove(storage_file_name)

        self.get_logger(username=username).info(
            f"Deleted user '{username}'.")
            
        del self.users[username]
        self.save()

    def get_users(self) -> List[str]:
        self.load()
        return list(self.users.keys())

    def get_logger(
        self,
        *,
        username: str
    ) -> Logger:
        logger = getLogger(self.application_details.APPLICATION_NAME)

        log_level: Union[str, int, Dict[str, str], List[str]] = self.application_details.get(
            key="LOG_LEVEL", userhash=self.users[username].USERHASH)

        if not isinstance(log_level, int):
            raise TypeError("Invalid log_level")

        log_file_name: Union[str, int, Dict[str, str], List[str]] = self.application_details.get(
            key="LOG_FILE_NAME", userhash=self.users[username].USERHASH)

        if not isinstance(log_file_name, str):
            raise TypeError("Invalid log_file_name")

        log_structure: Union[str, int, Dict[str, str], List[str]] = self.application_details.get(
            key="LOG_STRUCTURE", userhash=self.users[username].USERHASH)

        if not isinstance(log_structure, str):
            raise TypeError("Invalid log_structure")

        logger.setLevel(log_level)
        formatter = Formatter(log_structure)
        file_handler = FileHandler(log_file_name)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        return logger
    
    def get_storage(
            self,
            *,
            username: str,
            secret: str
    ) -> EPC:
        storage_file_name: Union[str, int, Dict[str, str], List[str]] = self.application_details.get(
            key="STORAGE_FILE_NAME", userhash=self.users[username].USERHASH)

        if not isinstance(storage_file_name, str):
            raise TypeError("Invalid storage_file_name")
        
        return EPC(
            file_path=storage_file_name,
            secret=secret,
            symmetric_encryption_type=self.users[username].SYMMETRIC_ENCRYPTION_TYPE,
            hash_type=self.users[username].HASH_TYPE,
            logger=self.get_logger(username=username)
        )
    
    def import_config(
            self,
            *,
            username: str,
            secret: str,
            file_path: str
    ) -> None:
        if not isinstance(username, str):
            raise TypeError("Username must be of type 'str'.")

        if not isinstance(file_path, str):
            raise TypeError("File path must be of type 'str'.")

        if username not in self.users:
            raise ValueError(
                f"User '{username}' not found in the configuration.")

        self.load()

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File '{file_path}' not found.")

        storage_file_name: Union[str, int, Dict[str, str], List[str]] = self.application_details.get(
            key="STORAGE_FILE_NAME", userhash=self.users[username].USERHASH)

        if not isinstance(storage_file_name, str):
            raise TypeError("Invalid storage_file_name")

        with open(file_path, "r") as file:
            data = json.load(file)

        if data["version"] != self.application_details.CONFIG_VERSION:
            raise ValueError("Invalid configuration file version.")
        else:
            del data["version"]
        
        data["USERHASH"] = self.users[username].USERHASH

        self.delete(username=username)
        
        self.users[username] = UserDetails(**data)

        storage_file_path: Union[str, int, Dict[str, str], List[str]] = self.application_details.get(
            key="STORAGE_FILE_NAME", userhash=self.users[username].USERHASH)

        if not isinstance(storage_file_path, str):
            raise TypeError("storage_file_path must be string.")

        log_file_path: Union[str, int, Dict[str, str], List[str]] = self.application_details.get(
            key="LOG_FILE_NAME", userhash=self.users[username].USERHASH)

        if not isinstance(log_file_path, str):
            raise TypeError("log_file_path must be string.")

        EPC.create(
            secret=secret,
            symmetric_encryption_type=self.users[username].SYMMETRIC_ENCRYPTION_TYPE,
            hash_type=self.users[username].HASH_TYPE,
            file_path=storage_file_path
        )

        with open(log_file_path, "w+") as file:
            file.write(f"File created at {datetime.now().isoformat()}.")

        self.save()

    def export_config(
            self,
            *,
            username: str
    ) -> str:
        if not isinstance(username, str):
            raise TypeError("Username must be of type 'str'.")

        if username not in self.users:
            raise ValueError(
                f"User '{username}' not found in the configuration.")

        self.load()

        file_path: Union[str, int, Dict[str, str], List[str]] = self.application_details.get(
            key="EXPORT_CONFIG_FILE_NAME", userhash=self.users[username].USERHASH)
        
        if not isinstance(file_path, str):
            raise TypeError("Invalid file_path")

        counter: int = 1
        new_file_path: str = file_path
        while os.path.exists(new_file_path):
            new_file_path = file_path.replace(
                self.application_details.CONFIG_FILE_EXTENSION, f"_{counter}{self.application_details.CONFIG_FILE_EXTENSION}")

        data: Dict[str, Union[str, bool, int]] = self.users[username].model_dump()

        data["version"] = self.application_details.CONFIG_VERSION
        del data["USERHASH"]
        
        os.makedirs(os.path.dirname(new_file_path), exist_ok=True)

        with open(new_file_path, "w+") as file:
            json.dump(data, file, indent=4)

        return new_file_path