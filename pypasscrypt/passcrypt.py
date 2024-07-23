"""
Password Manager package.

This module provides various utility classes and constants for password management,
encryption, and storage.
"""

from datetime import datetime
import sys
from InquirerPy import inquirer
import json
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import pyperclip
from time import sleep
from string import ascii_uppercase, ascii_lowercase, digits, punctuation
from secrets import choice, randbelow
from random import sample
from typing import List, Dict, Any, Optional, Literal, Tuple, Callable
import re
from cryptography.fernet import Fernet, InvalidToken
import hashlib
import base64
from pathlib import Path
import logging
from tkinter import filedialog

SIMILAR_CHARS: Dict[str, str] = {
    "o": "0", "0": "o",
    "s": "5", "5": "s",
    "b": "8", "8": "b",
    "z": "2", "2": "z",
    "q": "9", "9": "q",
    "1": "l", "l": "1",
    "3": "e", "e": "3",
    "a": "4", "4": "a",
    "t": "7", "7": "t"
}
"""
Dictionary of characters that are visually similar and can be easily confused.

Key-value pairs where the key is a character and the value is a string
of characters that look similar to the key.
"""

CONTEXT_FILTER: List[str] = [
    "gmail", "email", "com", "in", "co", "uk", "outlook",
    "onedrive", "yahoo", "google", "test", "password",
    "admin", "user", "login", "secure", "key", "root",
    "123456", "qwerty", "abc123", "password123", "letmein",
    "welcome", "admin123", "123456789", "12345678", "12345",
    "1234567", "1234567890", "password1", "1234", "password1234",
    "password12", "password12345", "password123456", "password1234567",
    "password12345678", "password123456789", "password1234567890",
    "default", "admin1", "admin2", "user1", "user2",
    "welcome1", "test123", "guest", "guest1", "guest123",
    "changeme", "changeme123", "root123", "rootpass", "system",
    "sysadmin", "superuser", "administrator", "manager", "testuser",
    "public", "demo", "example", "temp", "temp123",
    "tempuser", "publicuser", "public123", "trial", "trial123"
]
"""
List of context filters to exclude from password generation.

Contains strings that are commonly used in passwords and should be avoided
to ensure the generated passwords are secure.
"""

APPLICATION_NAME = "PassCrypt"
"""
The name of the application.
"""

LOCATION = os.getenv('PROGRAMDATA', "")
"""
The location to store the application data.
"""

DIRECTORY = ".passcrypt"
"""
The directory to store the application data.
"""

FILENAME = "passcrypt"
"""
The name of the storage file.
"""

EXTENSION = "epc"
"""
The extension of the storage file.
"""

DOWNLOADS = os.path.join(Path.home(), "Downloads")
"""
The default downloads directory.
"""

EXPORT_DIRECTORY = "passcrypt_exports"
"""
The directory to store exported data.
"""

PATHS = {
    'LOG_FILE': os.path.join(LOCATION, DIRECTORY, f"{FILENAME}.log"),
    'STORAGE_FILE': os.path.join(LOCATION, DIRECTORY, f"{FILENAME}.{EXTENSION}"),
    'EXPORT_PATH': os.path.join(DOWNLOADS, EXPORT_DIRECTORY)
}
"""
Dictionary of paths used by the application.

Contains key-value pairs where the key is a description of the path
and the value is the actual path used by the application.
"""

if not os.path.exists(PATHS['LOG_FILE']):
    os.makedirs(os.path.dirname(PATHS['LOG_FILE']), exist_ok=True)
    with open(PATHS['LOG_FILE'], "w") as file:
        file.write("")

logging.basicConfig(
    filename=PATHS['LOG_FILE'],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class CryptoHandler:
    """
    A class to handle encryption and decryption of data using Fernet symmetric encryption.
    """

    @staticmethod
    def get_cipher(input_string: str) -> Fernet:
        """
        Generate a Fernet cipher object using the input string as the key.

        :param input_string: The input string to generate the key.
        :return: A Fernet cipher object.
        """
        hash_digest = hashlib.sha256(input_string.encode()).digest()
        base64_key = base64.urlsafe_b64encode(hash_digest[:32])
        return Fernet(base64_key)

    @staticmethod
    def encrypt(data: Dict[str, Any], password: str) -> bytes:
        """
        Encrypt the given data using the provided password.

        :param data: The data to encrypt, as a dictionary.
        :param password: The password to use for encryption.
        :return: Encrypted data as bytes.
        """
        json_str = json.dumps(data)
        cipher = CryptoHandler.get_cipher(password)
        encrypted_data = cipher.encrypt(json_str.encode())
        return encrypted_data

    @staticmethod
    def decrypt(encrypted_data: bytes, password: str) -> Dict[str, Any]:
        """
        Decrypt the given encrypted data using the provided password.

        :param encrypted_data: The data to decrypt, as bytes.
        :param password: The password to use for decryption.
        :return: The decrypted data as a dictionary.
        :raises: Exception if decryption fails.
        """
        cipher = CryptoHandler.get_cipher(password)
        try:
            decrypted_data = cipher.decrypt(encrypted_data)
        except Exception as e:
            raise ValueError(
                "Decryption failed. Check the password and data."
            ) from e

        json_data = json.loads(decrypted_data.decode())
        return json_data

    @staticmethod
    def hash(data: str) -> str:
        """
        Compute the SHA-256 hash of the given data.

        :param data: The data to hash, as a string.
        :return: The SHA-256 hash of the data.
        """
        return hashlib.sha256(data.encode()).hexdigest()


class PasswordGenerator:
    """
    A class to generate passwords based on given context and constraints.
    """

    @staticmethod
    def is_valid_context(s: str) -> bool:
        """
        Check if the string matches any context filter.

        :param s: The string to check.
        :return: True if the string does not match any context filter, False otherwise.
        """
        return not re.search(r'\b(' + '|'.join(CONTEXT_FILTER) + r')\b', s, re.IGNORECASE)

    @staticmethod
    def break_context(s: str) -> List[str]:
        """
        Break the context into smaller parts based on non-word characters.

        :param s: The string to break.
        :return: A list of valid context parts.
        """
        pattern = r'[^\w\s]'
        result = re.split(pattern, s)
        return [substr.strip() for substr in result if substr.strip() and PasswordGenerator.is_valid_context(substr)]

    @staticmethod
    def generate_password(
            context: List[str],
            length: int = 15,
            upper_case: bool = True,
            lower_case: bool = True,
            numbers: bool = True,
            symbols: bool = True,
            exclude_similar: bool = False
    ) -> str:
        """
        Generate a password based on the given parameters and context.

        :param context: The list of context strings.
        :param length: The desired length of the password.
        :param upper_case: Whether to include uppercase letters.
        :param lower_case: Whether to include lowercase letters.
        :param numbers: Whether to include numbers.
        :param symbols: Whether to include symbols.
        :param exclude_similar: Whether to exclude similar characters.
        :return: The generated password.
        :raises ValueError: If the length is not a positive number or no character types are allowed.
        """
        if length <= 0:
            raise ValueError("Length of password must be a natural number.")

        allowed_chars = ''
        if upper_case:
            allowed_chars += ascii_uppercase
        if lower_case:
            allowed_chars += ascii_lowercase
        if numbers:
            allowed_chars += digits
        if symbols:
            allowed_chars += punctuation

        if not allowed_chars:
            raise ValueError(
                "No characters available to generate password. Ensure at least one type of character is allowed.")

        context_list = []
        for string in context:
            context_list += PasswordGenerator.break_context(string)

        if not context_list:
            context_list = context

        password = []
        for item in context_list:
            if randbelow(2) == 1:
                password.append(item)
            else:
                password.append("".join([choice(allowed_chars)
                                         for _ in range(len(item))]))

        password_str = "".join(sample(password, len(password)))

        # Replace similar characters if required
        if exclude_similar:
            password_str = ''.join(
                [SIMILAR_CHARS.get(ch, ch) for ch in password_str])

        # Ensure the password meets the length requirement
        if len(password_str) < length:
            password_str += ''.join([choice(allowed_chars)
                                     for _ in range(length - len(password_str))])
        elif len(password_str) > length:
            password_str = password_str[:length]

        for letter in password_str:
            if letter not in allowed_chars:
                password_str = password_str.replace(
                    letter, choice(allowed_chars))

        return password_str


class Storage:
    """
    A class to manage storage of passwords securely.
    """

    def __init__(self, password: str, new: bool) -> None:
        """
        Initialize the Storage object.

        :param password: The master password for the storage.
        :param new: Whether to create a new storage file or load an existing one.
        :return: None
        """
        self.__STORAGE: Dict[str, Dict[str, str]] = {}
        self.__SECRET = CryptoHandler.hash(password)
        if new:
            self.__save()
        else:
            self.__load()

    def __load(self) -> None:
        """
        Load the passwords from the storage file.
        """
        try:
            with open(PATHS["STORAGE_FILE"], "rb") as STORAGE_FILE:
                data = CryptoHandler.decrypt(
                    STORAGE_FILE.read(), self.__SECRET)
                self.__STORAGE = data.get("STORAGE", {})
        except Exception as e:
            print(f"Error loading data: {e}")

    def __save(self) -> None:
        """
        Save the passwords to the storage file.
        """
        with open(PATHS["STORAGE_FILE"], "wb") as STORAGE_FILE:
            encrypted_data = CryptoHandler.encrypt(
                {"STORAGE": self.__STORAGE}, self.__SECRET)
            STORAGE_FILE.write(encrypted_data)

    def validate_secret(self, secret: str) -> bool:
        """
        Validate the secret against the master password hash.

        :param secret: The secret to validate.
        :return: True if the secret is valid, False otherwise.
        """
        return CryptoHandler.hash(secret) == self.__SECRET  # Validate the secret

    def add_password(self, site: str, username: str, password: str) -> None:
        """
        Add a password to the storage.

        :param site: The site for which the password is being added.
        :param username: The username associated with the password.
        :param password: The password to store.
        :return: None
        """
        self.__load()
        if site not in self.__STORAGE:
            self.__STORAGE[site] = {}
        self.__STORAGE[site][username] = password
        self.__save()

    def remove_password(self, site: str, username: str) -> None:
        """
        Remove a password from the storage.

        :param site: The site for which the password is being removed.
        :param username: The username associated with the password.
        :return: None
        """
        self.__load()
        if len(self.get_username_for_site(site)) == 1:
            del self.__STORAGE[site]
        else:
            del self.__STORAGE[site][username]
        self.__save()

    def edit_password(self, site: str, username: str, new_site: str, new_username: str, new_password: str) -> None:
        """
        Edit a password in the storage.

        :param site: The site for which the password is being edited.
        :param username: The username associated with the password.
        :param new_site: The new site for the password.
        :param new_username: The new username associated with the password.
        :param new_password: The new password to store.
        :return: None
        """
        self.remove_password(site, username)
        self.add_password(new_site, new_username, new_password)

    def list_all(self) -> List[Tuple[str, str]]:
        """
        List all passwords in the storage.

        :return: A list of all passwords in the storage.
        """
        self.__load()
        data = []
        for site, credentials in self.__STORAGE.items():
            for username in credentials.keys():
                data.append((site, username))
        return data

    def get_all_sites(self) -> List[str]:
        """
        Get all sites in the storage.

        :return: A list of all sites in the storage.
        """
        self.__load()
        return list(self.__STORAGE.keys())

    def get_all_usernames(self) -> List[str]:
        """
        Get all usernames for a site in the storage.

        :return: A list of all usernames in the storage.
        """
        self.__load()
        data = []
        for credentials in self.__STORAGE.values():
            for username in credentials.keys():
                data.append(username)
        return list(set(data))

    def get_username_for_site(self, site: str) -> List[str]:
        """
        Get the username for a site in the storage.

        :param site: The site for which to retrieve the username.
        :return: A list of usernames for the site.
        """
        self.__load()
        return list(self.__STORAGE.get(site, {}).keys())

    def get_password_for_site(self, site: str, username: str) -> Optional[str]:
        """
        Get the password for a site in the storage.

        :param site: The site for which to retrieve the password.
        :param username: The username associated with the password.
        :return: The password for the site, or None if not found.
        """
        self.__load()
        return self.__STORAGE.get(site, {}).get(username, None)

    def site_exist(self, site: str) -> bool:
        """
        Check if a site exists in the storage.

        :param site: The site to check.
        :return: True if the site exists, False otherwise.
        """
        self.__load()
        return bool(self.__STORAGE.get(site, False))

    def username_exist(self, site: str, username: str) -> bool:
        """
        Check if a username exists for a site in the storage.

        :param site: The site to check.
        :param username: The username to check.
        :return: True if the username exists, False otherwise.
        """
        self.__load()
        if self.site_exist(site):
            return bool(self.__STORAGE.get(site, {}).get(username, False))
        return False

    def clear_all_data(self) -> None:
        """
        Clear all passwords from the storage.

        :return: None
        """
        self.__STORAGE = {}
        self.__save()

    @staticmethod
    def clear_logs() -> None:
        """
        Clear the logs.

        :return: None
        """
        with open(PATHS["LOG_FILE"], "w") as LOG_FILE:
            LOG_FILE.write("")

    def change_master_password(self, new_password: str) -> None:
        """
        Change the master password for the storage.

        :param new_password: The new master password.
        :return: None
        """
        self.__SECRET = CryptoHandler.hash(new_password)
        self.__save()

    def export_storage(self, secret: str) -> str:
        """
        Export the storage data.

        :param secret: The secret to encrypt the storage data.
        :return: The encrypted storage data.
        """
        self.__load()
        file_path = os.path.join(
            PATHS["EXPORT_PATH"],
            f"passcrypt_storage_{str(CryptoHandler.hash(str(datetime.now())))}.{EXTENSION}"
        )

        if not os.path.exists(PATHS["EXPORT_PATH"]):
            os.makedirs(PATHS["EXPORT_PATH"], exist_ok=True)

        with open(file_path, "+wb") as EXPORT_PATH:
            encrypted_data = CryptoHandler.encrypt(
                self.__STORAGE,
                CryptoHandler.hash(secret)
            )
            EXPORT_PATH.write(encrypted_data)
        return file_path

    @staticmethod
    def export_logs() -> str:
        """
        Export the logs.

        :return: The path to the exported logs.
        """
        file_path = os.path.join(
            PATHS["EXPORT_PATH"],
            f"passcrypt_logs_{str(CryptoHandler.hash(str(datetime.now())))}.log"
        )

        if not os.path.exists(PATHS["EXPORT_PATH"]):
            os.makedirs(PATHS["EXPORT_PATH"], exist_ok=True)

        with open(file_path, "w") as export_file:
            with open(PATHS["LOG_FILE"], "r") as log_file:
                export_file.write(log_file.read())
        return file_path

    def import_storage(self, secret: str, file_path: str, confirm: Callable) -> bool:
        """
        Import the storage data.

        :param secret: The secret to decrypt the storage data.
        :param file_path: The path to the file to import.
        :param confirm: The confirmation function.
        :return: True if the import is successful, False otherwise.
        """
        with open(file_path, "rb") as IMPORT_PATH:
            try:
                data = CryptoHandler.decrypt(
                    IMPORT_PATH.read(),
                    CryptoHandler.hash(secret)
                )
            except InvalidToken:
                return False

            for site, credentials in data.items():
                if site not in self.__STORAGE:
                    self.__STORAGE[site] = {}

                for username, password in credentials.items():
                    if username not in self.__STORAGE[site]:
                        self.__STORAGE[site][username] = password
                    else:
                        if self.__STORAGE[site][username] != password:
                            override = confirm(
                                "CONFIRM",
                                input_message=f"Password for {site} - {username} already exists. Override?",
                                default=False
                            )
                            # Move the cursor up one line
                            sys.stdout.write('\033[F')
                            sys.stdout.write('\033[K')  # Clear the line
                            sys.stdout.flush()
                            if override == 'y':
                                self.__STORAGE[site][username] = password
            self.__save()
        return True


class UserInterface:
    """
    A class to handle the user interface for the Password Manager.

    Methods:
        add_password(): Add a password to the storage.
        remove_password(): Remove a password from the storage.
        edit_password(): Edit a password in the storage.
        list_all(): List all passwords in the storage.
        settings(): Display the settings menu.
        clear_logs(): Clear the logs.
        remove_pc(): Remove the PassCrypt storage file.
        export_logs(): Export the PassCrypt logs to a file.
        export_pc(): Export the PassCrypt storage to a file.
        import_pc(): Import a PassCrypt storage from a file.
        clear_all_data(): Clear all passwords from the storage.
        change_master_password(): Change the master password for the storage.
    """

    def __init__(self) -> None:
        """
        Initialize the UserInterface object.

        :return: None
        """
        self.console = Console()

    @staticmethod
    def clear_console() -> None:
        """
        Clear the terminal screen.

        :return: None
        """
        os.system('cls' if os.name == 'nt' else 'clear')
        # .

    @staticmethod
    def clear_last_line() -> None:
        """
        Clear the last line in the terminal.

        :return: None
        """
        sys.stdout.write('\033[F')  # Move the cursor up one line
        sys.stdout.write('\033[K')  # Clear the line
        sys.stdout.flush()

    def new_page(self, title: str, subtitle: str, message: str = "") -> None:
        """
        Print a new page separator.

        :param title: The title of the page.
        :param subtitle: The subtitle of the page.
        :param message: The message to show in panel.
        :return: None
        """

        self.clear_console()

        self.console.print("\n\n")
        self.show_greet_panel(
            APPLICATION_NAME,
            f"[bold blue]{title}[/bold blue] - [yellow]{subtitle}[/yellow]",
            message
        )
        self.console.print("\n")

    def create_table(self, title: str, headers: List[str], data: List[List[str]]) -> None:
        """
        Create a table with the given title, headers, and data.

        :param title: The title of the table.
        :param headers: The headers of the table.
        :param data: The data for the table.
        :return: None
        """
        table = Table(title=title)
        for header in headers:
            table.add_column(header)
        for row in data:
            table.add_row(*row)

        self.console.print(table)

    def get_password(self, site: str, username: str) -> str:
        """
        Get a password from the user or generate one if not provided.

        :param site: The site for which the password is being generated.
        :param username: The username associated with the password.
        :return: The generated or provided password.
        """
        password = inquirer.text(
            message="Enter the password (Leave empty to generate a password):"
        ).execute()
        if not password:
            length = None
            while length is None:
                try:
                    length = int(inquirer.text(
                        message="Enter the length of the password:", default="15"
                    ).execute())
                except ValueError:
                    self.show_error("Length must be a number.")
                    length = None
            include_upper = inquirer.confirm(
                message="Include uppercase letters?", default=True
            ).execute()
            include_lower = inquirer.confirm(
                message="Include lowercase letters?", default=True
            ).execute()
            include_numbers = inquirer.confirm(
                message="Include numbers?", default=True
            ).execute()
            include_symbols = inquirer.confirm(
                message="Include symbols?", default=True
            ).execute()
            try:
                password = PasswordGenerator.generate_password(
                    [site, username], length, include_upper, include_lower, include_numbers, include_symbols
                )
            except ValueError as e:
                self.show_error(str(e))
                password = None
        else:
            confirm_password = inquirer.text(
                message="Confirm the password:"
            ).execute()
            if password != confirm_password:
                self.show_error("Passwords do not match.")
                password = None
        return password

    @staticmethod
    def master_validation(password: str) -> bool:
        """
        Validate the master password.

        :param password: The password to validate.
        :return: True if the password is valid, False otherwise.
        """
        if len(password) < 8:
            return False

        if not any(char.isdigit() for char in password):
            return False

        if not any(char.isupper() for char in password):
            return False

        if not any(char.islower() for char in password):
            return False

        if not any(char in punctuation for char in password):
            return False

        return True

    def get_master_password(self, message: str) -> str:
        """
        Get the master password from the user.

        :param message: The message to display to the user.
        :return: The master password provided by the user.
        """
        data = inquirer.text(
            message=message,
            validate=self.master_validation,
            is_password=True,
            invalid_message="The password must contain one uppercase, one lowercase, one symbol, and one digit and " +
                            "must be 8 or more characters"
        ).execute()
        self.clear_last_line()
        return data

    @staticmethod
    def get_selection(message: str, choices: List[str], default: Any = None, skip_message: str = "") -> str:
        """
        Get a selection from the user.

        :param message: The message to display to the user.
        :param choices: The choices to display to the user.
        :param default: The default choice.
        :param skip_message: The message to display for skipping the selection.
        :return: The selected choice.
        """
        local_choices = choices.copy()
        if skip_message:
            local_choices.insert(0, skip_message)
        return inquirer.select(
            message=message,
            choices=local_choices,
            border=True,
            default=default
        ).execute()

    @staticmethod
    def get_input(message: str, default: Any = None) -> str:
        """
        Get input from the user.

        :param message: The message to display to the user.
        :param default: The default input.
        :return: The input provided by the user.
        """
        return inquirer.text(
            message=message,
            default=default
        ).execute()

    def ui_input(
            self,
            mode: Literal["INPUT", "SELECTION", "BOTH", "PASSWORD", "MASTER_PASSWORD", "CONFIRM", "FILE"],
            selection_message: Optional[str] = None,
            choices: Optional[List[str]] = None,
            input_message: Optional[str] = None,
            skip_message: str = "",
            default: Any = "",
            site: Optional[str] = None,
            username: Optional[str] = None
    ) -> str:
        """
        Get input from the user based on the specified mode.

        :param mode: The mode to use for input.
        :param selection_message: The message for selection mode.
        :param choices: The choices for selection mode.
        :param input_message: The message for input mode.
        :param skip_message: The message for skipping the selection.
        :param default: The default input.
        :param site: The site for password mode.
        :param username: The username for password mode.
        :return: The input provided by the user.
        """
        data = None
        while not data:
            if mode == "SELECTION":
                if not choices:
                    raise ValueError(
                        "Choices and selection message must be provided for selection mode.")
                if not selection_message:
                    raise ValueError(
                        "Selection message must be provided for selection mode.")
                data = self.get_selection(
                    selection_message, choices, default, skip_message)
                if not data:
                    self.show_error("Selection cannot be empty.")
                    data = None

            elif mode == "INPUT":
                if not input_message:
                    raise ValueError(
                        "Input message must be provided for input mode.")
                data = self.get_input(input_message, default)

            elif mode == "BOTH":
                if not isinstance(choices, list):
                    raise ValueError(
                        "Choices must be provided for selection mode.")
                if not selection_message:
                    raise ValueError(
                        "Selection message must be provided for selection mode.")
                if not input_message:
                    raise ValueError(
                        "Input message must be provided for input mode.")
                if choices:
                    data = self.get_selection(
                        selection_message, choices, default, skip_message)
                    print(data)
                if data == skip_message or not data:
                    data = self.get_input(input_message, default)

            elif mode == "MASTER_PASSWORD":
                if not input_message:
                    raise ValueError(
                        "Input message must be provided for input mode.")
                data = self.get_master_password(input_message)

            elif mode == "PASSWORD":
                if not site:
                    raise ValueError(
                        "Site and username must be provided for password mode.")
                if not username:
                    raise ValueError(
                        "Username must be provided for password mode.")
                data = self.get_password(site, username)

            elif mode == "CONFIRM":
                if not input_message:
                    raise ValueError(
                        "Input message must be provided for input mode.")
                data = "y" if inquirer.confirm(
                    message=input_message,
                    default=default
                ).execute() else "n"

            elif mode == "FILE":
                data = inquirer.filepath(
                    message="Enter the file path (press ENTER for GUI):",
                    default="gui"
                ).execute()

                if data == "gui":
                    data = filedialog.askopenfilename(
                        title="Select a file to import",
                        filetypes=[("PassCrypt Files", f"*.{EXTENSION}")],
                        initialdir=DOWNLOADS
                    )

                if not data:
                    self.show_error("File path cannot be empty.")
                    data = None
                    continue

                extension = os.path.splitext(data)[1]
                if extension != f".{EXTENSION}":
                    self.show_error(
                        f"Invalid file type. Please select a file with the extension '.{EXTENSION}'.")
                    data = None
                    continue

                if not os.path.exists(data):
                    self.show_error("File does not exist. Try again.")
                    data = None
                    continue

        return data

    def wait(self) -> None:
        """
        Wait for the user to press ENTER.

        :return: None
        """
        self.show_info("\nPress ENTER to continue.")
        input()

    def show_error(self, message: str) -> None:
        """
        Display an error message to the user.

        :param message: The error message to display.
        :return: None
        """
        self.console.print(f"[bold red]{message}[/bold red]")
        sleep(1)

    def show_success(self, message: str) -> None:
        """
        Display a success message to the user.

        :param message: The success message to display.
        :return: None
        """
        self.console.print(f"[bold green]{message}[/bold green]")
        sleep(1)

    def show_info(self, message: str) -> None:
        """
        Display an informational message to the user.

        :param message: The informational message to display.
        :return: None
        """
        self.console.print(f"[bold blue]{message}[/bold blue]")
        sleep(1)

    def show_warning(self, message: str) -> None:
        """
        Display a warning message to the user.

        :param message: The warning message to display.
        :return: None
        """
        self.console.print(f"[bold yellow]{message}[/bold yellow]")
        sleep(1)

    def show_greet_panel(self, title: str, subtitle: str, message: str) -> None:
        """
        Display a warning panel to the user.

        :param title: The title of the panel.
        :param subtitle: The subtitle of the panel.
        :param message: The warning message to display.
        :return: None
        """
        self.console.print(Panel(
            message,
            title=title,
            title_align="center",
            subtitle=subtitle,
            subtitle_align="center",
            border_style="cyan",
            style="cyan",
            padding=(1, 2)
        ), "\n")

    def show_warning_panel(self, title: str, subtitle: str, message: str) -> None:
        """
        Display a warning panel to the user.

        :param title: The title of the panel.
        :param subtitle: The subtitle of the panel.
        :param message: The warning message to display.
        :return: None
        """
        self.console.print(Panel(
            message,
            title=title,
            title_align="center",
            subtitle=subtitle,
            subtitle_align="center",
            border_style="yellow",
            style="yellow",
            padding=(1, 2)
        ), "\n")

    def show_error_panel(self, title: str, subtitle: str, message: str) -> None:
        """
        Display an error panel to the user.

        :param title: The title of the panel.
        :param subtitle: The subtitle of the panel.
        :param message: The error message to display.
        :return: None
        """
        self.console.print(Panel(
            message,
            title=title,
            title_align="center",
            subtitle=subtitle,
            subtitle_align="center",
            border_style="red",
            style="red",
            padding=(1, 2)
        ), "\n")

    def show_success_panel(self, title: str, subtitle: str, message: str) -> None:
        """
        Display a success panel to the user.

        :param title: The title of the panel.
        :param subtitle: The subtitle of the panel.
        :param message: The success message to display.
        :return: None
        """
        self.console.print(Panel(
            message,
            title=title,
            title_align="center",
            subtitle=subtitle,
            subtitle_align="center",
            border_style="green",
            style="green",
            padding=(1, 2)
        ), "\n")

    def show_info_panel(self, title: str, subtitle: str, message: str) -> None:
        """
        Display an informational panel to the user.

        :param title: The title of the panel.
        :param subtitle: The subtitle of the panel.
        :param message: The informational message to display.
        :return: None
        """
        self.console.print(Panel(
            message,
            title=title,
            title_align="center",
            subtitle=subtitle,
            subtitle_align="center",
            border_style="blue",
            style="blue",
            padding=(1, 2)
        ), "\n")


class PasswordManager:
    """
    A class to manage the Password Manager application.
    """

    def __init__(self) -> None:
        """
        Initialize the PasswordManager object.

        :return: None
        """
        self.ui = UserInterface()

    def __call__(self) -> None:
        """
        Run the Password Manager application.

        :return: None
        """
        logging.info("Starting PassCrypt Application")
        if not os.path.exists(PATHS["STORAGE_FILE"]):
            logging.info("Initializing PassCrypt")
            status, self.storage = self.init_pm()
        else:
            logging.info("Logging into PassCrypt")
            status, self.storage = self.login()

        if status:
            logging.info("Access granted!")
            self.main_menu()
        else:
            logging.error("Access denied!")
            self.ui.show_error(
                "An error occurred while initializing the Password Manager")

    def init_pm(self) -> Tuple[bool, Optional[Storage]]:
        """
        Initialize the Password Manager

        :return: A tuple containing the status and the storage object.
        """
        self.ui.new_page(
            f"Initialization",
            "Press ctrl+c to exit.",
            "Introducing PassCrypt, the ultimate solution for secure and effortless password management. " +
            "With advanced encryption technology, PassCrypt ensures that your passwords are stored " +
            "safely, protecting them from unauthorized access. Our user-friendly interface makes it easy " +
            "to encrypt, store, and retrieve your passwords, offering you peace of mind and convenience. " +
            "Whether you're managing passwords for personal use or for a team, PassCrypt provides robust " +
            "security features to keep your sensitive information safe. Trust PassCrypt for reliable " +
            "password encryption and storage, so you can focus on what matters most without worrying " +
            "about password security. Try PassCrypt today!"
        )
        os.makedirs(os.path.dirname(PATHS["STORAGE_FILE"]), exist_ok=True)
        master_password = self.generate_master()
        try:
            storage = Storage(master_password, True)
        except Exception as e:
            self.ui.show_error(
                "An error occurred while initializing the Password Manager." + str(e))
            return False, None
        return True, storage

    def generate_master(self):
        """
        Generate the master password for the Password Manager.

        :return: The generated master password.
        """
        final_password = None
        while not final_password:
            master_password = self.ui.ui_input(
                "MASTER_PASSWORD",
                input_message="Set the Master Password:"
            )
            master_password_confirm = self.ui.ui_input(
                "MASTER_PASSWORD",
                input_message="Confirm the Master Password:"
            )
            if master_password == master_password_confirm:
                final_password = master_password
            else:
                self.ui.show_error("Passwords do not match. Try again.")
        return final_password

    def login(self) -> Tuple[bool, Optional[Storage]]:
        """
        Login to access the password manager

        :return: A tuple containing the status and the storage object.
        """
        self.ui.new_page(f"Login", "Press ctrl+c to exit.")
        master_password = self.ui.ui_input(
            "MASTER_PASSWORD",
            input_message="Enter the Master Password:"
        )

        try:
            storage = Storage(master_password, False)
            self.ui.show_success("Access granted! Welcome to PassCrypt.")
            return True, storage
        except InvalidToken:
            self.ui.show_error("Invalid Master Password! Access denied.")
            return False, None

    def main_menu(self) -> None:
        """
        Display the main menu of the Password Manager.

        :return: None
        """
        self.ui.new_page("Main Menu", "Press ctrl+c to exit.")
        choices = {
            "List All": self.list_all,
            "Add Password": self.add_password,
            "Edit Password": self.edit_password,
            "Remove Password": self.remove_password,
            "Settings": self.authenticate
        }

        option = self.ui.ui_input(
            "SELECTION",
            selection_message="Choose an option:",
            choices=list(choices.keys()),
            default="List All"
        )
        try:
            choices[option]()
        except KeyboardInterrupt:
            self.ui.show_info("Returning to the Main Menu.")
        self.main_menu()

    def authenticate(self) -> None:
        """
        Authenticate the user to access the settings.

        :return: None
        """
        self.ui.new_page("Authentication",
                         "Press ctrl+c to return to the Main Menu.")

        master_password = self.ui.ui_input(
            "MASTER_PASSWORD",
            input_message="Enter the Master Password:"
        )
        if self.storage and not self.storage.validate_secret(master_password):
            self.ui.show_error(
                "Invalid Master Password! Access denied.")
        else:
            self.settings()

    def add_password(self) -> None:
        """
        Add a password to the storage.

        :return: None
        """
        self.ui.new_page("Add Password", "Press ctrl+c to abort.")

        if not self.storage:
            self.ui.show_error(
                "An error occurred while accessing the storage.")
            return

        sites = self.storage.get_all_sites()
        usernames = self.storage.get_all_usernames()

        site = self.ui.ui_input(
            "BOTH",
            selection_message="Select a site/application (Press ENTER to add new site/application):",
            choices=sites,
            input_message="Enter new site/application:",
            skip_message="Add new site/application"
        )

        usernames = [
            username
            for username
            in usernames
            if username not in self.storage.get_username_for_site(site)
        ]

        username = None
        while not username:
            username = self.ui.ui_input(
                "BOTH",
                selection_message="Select a username (Press ENTER to add new username):",
                choices=usernames,
                input_message="Enter new username:",
                skip_message="Add new username"
            )
            if self.storage.username_exist(site, username):
                self.ui.show_error(
                    f"Password for {site} - {username} already exists!")
                username = None

        self.storage.add_password(
            site, username, self.ui.ui_input(
                "PASSWORD",
                site=site,
                username=username
            )
        )
        self.ui.show_success(
            f"Password for {site} - {username} added successfully!")
        pyperclip.copy(self.storage.get_password_for_site(site, username))
        logging.info(f"Password for {site} - {username} added successfully!")

    def remove_password(self) -> None:
        """
        Remove a password from the storage.

        :return: None
        """
        self.ui.new_page("Remove Password", "Press ctrl+c to abort.")

        if not self.storage:
            self.ui.show_error(
                "An error occurred while accessing the storage.")
            return

        sites = self.storage.get_all_sites()
        if len(sites) == 0:
            self.ui.show_error("No passwords found to remove!")
            return

        site = None
        while not site:
            site = self.ui.ui_input(
                "SELECTION",
                selection_message="Select a site/application to remove the password:",
                choices=sites
            )

        username = None
        while not username:
            username = self.ui.ui_input(
                "SELECTION",
                selection_message="Select a username to remove the password:",
                choices=self.storage.get_username_for_site(site)
            )
        if self.ui.ui_input(
                "CONFIRM",
                input_message=f"Are you sure you want to remove the password for {username} - {site}?",
                default=False
        ) == 'y':
            self.storage.remove_password(site, username)
            self.ui.show_success(
                f"Password for {site} - {username} removed successfully!")
            logging.info(
                f"Password for {site} - {username} removed successfully!")
        else:
            self.ui.show_info(
                f"Returning to the Main Menu.")

    def edit_password(self) -> None:
        """
        Edit a password in the storage.

        :return: None
        """
        self.ui.new_page("Edit Password", "Press ctrl+c to abort.")

        if not self.storage:
            self.ui.show_error(
                "An error occurred while accessing the storage.")
            return

        sites = self.storage.get_all_sites()
        if len(sites) == 0:
            self.ui.show_error("No passwords found to edit!")
            return

        previous_site = self.ui.ui_input(
            "SELECTION",
            selection_message="Select a site/application to edit the password:",
            choices=sites
        )

        previous_user = self.ui.ui_input(
            "SELECTION",
            selection_message="Select a username to edit the password:",
            choices=self.storage.get_username_for_site(previous_site)
        )

        sites.remove(previous_site)

        if self.ui.ui_input(
                "CONFIRM",
                input_message="Change the site/application name?",
                default=False
        ) == 'y':
            self.ui.clear_last_line()
            new_site = None
            while not new_site:
                new_site = self.ui.ui_input(
                    "BOTH",
                    selection_message="Select the site/application (Press ENTER to keep the current site/application):",
                    choices=sites,
                    input_message="Enter the new site/application name:",
                    skip_message="Add new site/application"
                )
                if previous_user in self.storage.get_username_for_site(new_site):
                    self.ui.show_error(
                        f"Password for {new_site} - {previous_user} already exists!")
                    self.ui.clear_last_line()
                    new_site = None
        else:
            new_site = previous_site

        if self.storage.site_exist(new_site):
            usernames = self.storage.get_username_for_site(new_site)
            usernames.remove(previous_user)
        else:
            usernames = []

        if self.ui.ui_input(
                "CONFIRM",
                input_message="Change the username?",
                default=False
        ) == 'y':
            self.ui.clear_last_line()
            new_user = self.ui.ui_input(
                "BOTH",
                selection_message="Select the username (Press ENTER to keep the current username):",
                choices=usernames,
                input_message="Enter the new username:",
                skip_message="Add new username"
            )
        else:
            new_user = previous_user

        if self.ui.ui_input(
                "CONFIRM",
                input_message="Change the password?",
                default=False
        ) == 'y':
            self.ui.clear_last_line()
            new_password = self.ui.ui_input(
                "PASSWORD",
                site=new_site,
                username=new_user
            )
        else:
            new_password = self.storage.get_password_for_site(
                previous_site, previous_user) or ""

        self.storage.edit_password(
            previous_site, previous_user, new_site, new_user, new_password)
        self.ui.show_success(
            f"Password for {previous_site} - {previous_user} edited successfully!")
        logging.info(
            f"Password for {previous_site} - {previous_user} edited successfully!")

    def list_all(self) -> None:
        """
        List all passwords in the storage.

        :return: None
        """
        if not self.storage:
            self.ui.show_error(
                "An error occurred while accessing the storage.")
            logging.error("An error occurred while accessing the storage.")
            return

        self.ui.new_page("List All Passwords",
                         "Press ctrl+c to return to the Main Menu.")

        if not self.storage.get_all_sites():
            self.ui.show_info("No passwords found!")
            return

        self.ui.create_table(
            "Stored Passwords",
            ["ID", "Site/Application", "Username"],
            [[str(idx), site, username] for idx, (site, username)
             in enumerate(self.storage.list_all(), start=1)]
        )

        if self.ui.ui_input(
                "CONFIRM",
                input_message="Copy a password?",
                default=False
        ) == 'y':
            self.ui.new_page(
                "Copy Password", "Press ctrl+c to return to the Main Menu.")
            choices = [
                f"{idx:>3}:  {site:>20} ->  {username:>20}"
                for idx, (site, username)
                in enumerate(self.storage.list_all(), start=1)
            ]
            selected = self.ui.ui_input(
                "SELECTION",
                selection_message="Select a password to copy:",
                choices=choices
            )

            site, username = self.storage.list_all()[
                int(choices.index(selected))]
            pyperclip.copy(self.storage.get_password_for_site(site, username))
            self.ui.show_success(
                f"Password for {site} - {username} copied to clipboard!\nReturning to the Main Menu.")
            logging.info(
                f"Password for {site} - {username} copied to clipboard!")
        else:
            self.ui.show_info(
                "Returning to the Main Menu.")

    def settings(self) -> None:
        """
        Display the settings menu.

        :return: None
        """
        self.ui.new_page(
            "Settings", "Press ctrl+c to return to the Main Menu.")

        choices = {
            "Return to Main Menu\n": lambda: self.ui.show_info("Returning to the Main Menu."),
            "Reset Master Password\n": self.change_master_password,
            "Import a PassCrypt storage\n": self.import_pc,
            "Export your PassCrypt storage": self.export_pc,
            "Export your PassCrypt logs\n": self.export_logs,
            "Clear all passwords": self.clear_all_data,
            "Clear logs\n": self.clear_logs,
            "Remove PassCrypt storage": self.remove_pc
        }

        option = self.ui.ui_input(
            "SELECTION",
            selection_message="Choose an option:",
            choices=list(choices.keys()),
            default="Return to Main Menu\n"
        )

        try:
            choices[option]()
        except KeyboardInterrupt:
            self.ui.show_info("Returning to the Main Menu.")

    def clear_logs(self) -> None:
        """
        Clear the logs.

        :return: None
        """

        if not self.storage:
            self.ui.show_error(
                "An error occurred while accessing the storage.")
            logging.error("An error occurred while accessing the storage.")
            return

        self.ui.new_page("Clear Logs", "Press ctrl+c to abort.")
        if self.ui.ui_input(
                "CONFIRM",
                input_message="Are you sure you want to clear the logs?",
                default=False
        ) == 'y':
            self.storage.clear_logs()
            self.ui.show_success("Logs cleared successfully!")
            logging.info("Logs cleared successfully!")
        else:
            self.ui.show_info("Returning to the Main Menu.")

    def remove_pc(self) -> None:
        """
        Remove the PassCrypt storage file.  

        :return: None
        """
        self.ui.new_page("Remove PassCrypt Storage",
                         "Press ctrl+c to abort.")
        self.ui.show_error_panel(
            "WARNING",
            "Remove PassCrypt Storage",
            "This action will remove the PassCrypt storage file and all its contents. This action is irreversible."
        )
        if self.ui.ui_input(
                "CONFIRM",
                input_message="Are you sure you want to remove the PassCrypt storage?",
                default=False
        ) == 'y':
            os.remove(PATHS["STORAGE_FILE"])
            self.ui.show_success("PassCrypt storage removed successfully!")
            logging.info("PassCrypt storage removed successfully!")
            os.system('cls' if os.name == 'nt' else 'clear')
            sys.exit(0)
        else:
            self.ui.show_info("Returning to the Main Menu.")

    def export_logs(self) -> None:
        """
        Export the PassCrypt logs to a file.

        :return: None
        """
        if not self.storage:
            self.ui.show_error(
                "An error occurred while accessing the storage.")
            logging.error("An error occurred while accessing the storage.")
            return
        self.ui.new_page("Export PassCrypt Logs", "Press ctrl+c to abort.")
        self.ui.show_info_panel(
            "INFO",
            "Export PassCrypt Logs",
            "This action will export the PassCrypt logs to a file."
        )
        if self.ui.ui_input(
                "CONFIRM",
                input_message="Are you sure you want to export the PassCrypt logs?",
                default=False
        ) == 'n':
            self.ui.show_info("Returning to the Main Menu.")
            return

        path = self.storage.export_logs()
        self.ui.show_success(
            f"PassCrypt logs exported successfully!\nFile saved at: {path}\nReturning to the Main Menu.")
        logging.info("PassCrypt logs exported successfully!")

        self.ui.wait()

    def export_pc(self) -> None:
        """
        Export the PassCrypt storage to a file.

        :return: None
        """
        if not self.storage:
            self.ui.show_error(
                "An error occurred while accessing the storage.")
            logging.error("An error occurred while accessing the storage.")
            return

        self.ui.new_page("Export PassCrypt Storage",
                         "Press ctrl+c to abort.")
        self.ui.show_info_panel(
            "INFO",
            "Confirm Export",
            "This action will export the PassCrypt storage to a file."
        )
        if not self.ui.ui_input(
                "CONFIRM",
                input_message="Are you sure you want to export the PassCrypt storage?",
                default=False
        ) == 'y':
            self.ui.show_info("Returning to the Main Menu.")
            return

        secret = self.ui.ui_input(
            "MASTER_PASSWORD",
            input_message="Enter key for encryption:"
        )

        path = self.storage.export_storage(secret)
        self.ui.show_success(
            f"PassCrypt storage exported successfully!\nFile saved at: {path}\nReturning to the Main Menu.")
        logging.info("PassCrypt storage exported successfully to: " + path)

        self.ui.wait()

    def import_pc(self) -> None:
        """
        Import a PassCrypt storage from a file.

        :return: None
        """
        if not self.storage:
            self.ui.show_error(
                "An error occurred while accessing the storage.")
            logging.error("An error occurred while accessing the storage.")
            return
        self.ui.new_page("Import PassCrypt Storage",
                         "Press ctrl+c to abort.")
        self.ui.show_error_panel(
            "WARNING",
            "Import PassCrypt Storage",
            """This action will import a PassCrypt storage file.
            It may have gibberish data.
            Make sure you trust the source of the file."""
        )
        path = self.ui.ui_input("FILE")

        final_password = self.ui.ui_input(
            "MASTER_PASSWORD",
            input_message="Enter key for decryption:"
        )

        self.storage.import_storage(final_password, path, self.ui.ui_input)
        self.ui.show_success(
            "PassCrypt storage imported successfully!\nReturning to the Main Menu.")
        logging.info("PassCrypt storage imported successfully!")
        self.ui.wait()

    def clear_all_data(self) -> None:
        """
        Clear all passwords from the storage.

        :return: None
        """
        if not self.storage:
            self.ui.show_error(
                "An error occurred while accessing the storage.")
            logging.error("An error occurred while accessing the storage.")
            return

        self.ui.new_page("Clear All Data", "Press ctrl+c to abort.")
        self.ui.show_error_panel(
            "WARNING",
            "Clear All Data",
            "This action will clear all passwords from the storage. This action is irreversible."
        )
        if not self.ui.ui_input(
                "CONFIRM",
                input_message="Are you sure you want to clear all passwords?",
                default=False
        ) == 'y':
            self.ui.show_info("Returning to the Main Menu.")
            return
        self.storage.clear_all_data()
        self.ui.show_success("All passwords cleared successfully!")
        logging.info("All passwords cleared successfully!")

    def change_master_password(self) -> None:
        """
        Change the master password for the storage.

        :return: None
        """
        if not self.storage:
            self.ui.show_error(
                "An error occurred while accessing the storage.")
            logging.error("An error occurred while accessing the storage.")
            return
        self.ui.new_page("Reset Master Password",
                         "Press ctrl+c to abort.")
        self.ui.show_error_panel(
            "WARNING",
            "Reset Master Password",
            "This action will reset the Master Password for the storage."
        )

        new_password = self.generate_master()
        self.storage.change_master_password(new_password)
        self.ui.show_success("Master Password reset successfully!")
        logging.info("Master Password reset successfully!")


def main():
    """
    Run the Password Manager application.

    :return: None
    """
    passcrypt = PasswordManager()
    try:
        passcrypt()
    except KeyboardInterrupt:
        print("\nExiting PassCrypt...")
        logging.info("Exiting PassCrypt")
        sleep(1)
        os.system('cls' if os.name == 'nt' else 'clear')
        sys.exit(0)
    except Exception as e:
        logging.error("An error occurred while running PassCrypt.")
        logging.error(str(e))


if __name__ == "__main__":
    main()
