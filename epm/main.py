from InquirerPy import inquirer
import json
import os
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
import pyperclip
from time import sleep
from string import ascii_uppercase, ascii_lowercase, digits, punctuation
from secrets import choice, randbelow
from random import sample
from typing import List, Dict
import re
from cryptography.fernet import Fernet
import hashlib
import base64


class CryptoHandler:

    @staticmethod
    def get_cypher(input_string):
        hash_digest = hashlib.sha256(input_string.encode()).digest()
        base64_key = base64.urlsafe_b64encode(hash_digest[:32])
        return Fernet(base64_key)

    @staticmethod
    def encrypt(data, password):
        json_str = json.dumps(data)
        encrypted_data = CryptoHandler.get_cypher(
            password).encrypt(json_str.encode())
        return encrypted_data

    @staticmethod
    def decrypt(encrypted_data, password):
        decrypted_data = CryptoHandler.get_cypher(
            password).decrypt(encrypted_data)
        json_data = json.loads(decrypted_data.decode())
        return json_data

    @staticmethod
    def hash(data):
        return hashlib.sha256(data.encode()).hexdigest()


class PasswordGenerator:
    context_filter: List[str] = [
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

    similar_chars: Dict[str, str] = {
        "i": "l", "l": "i",
        "o": "0", "0": "o",
        "s": "5", "5": "s",
        "b": "8", "8": "b",
        "g": "9", "9": "g",
        "z": "2", "2": "z",
        "q": "9", "9": "q",
        "1": "l", "l": "1",
        "3": "e", "e": "3",
        "a": "4", "4": "a",
        "t": "7", "7": "t"
    }

    @staticmethod
    def context_checker(s: str) -> bool:
        """Check if the string matches any context filter."""
        return not re.match(r'\b(' + '|'.join(PasswordGenerator.context_filter) + r')\b', s, re.IGNORECASE)

    @staticmethod
    def break_context(s: str) -> List[str]:
        """Break the context into smaller parts based on non-word characters."""
        pattern = r'[^\w\s]'
        result = re.split(pattern, s)
        return [substr.strip() for substr in result if substr.strip() and PasswordGenerator.context_checker(substr)]

    @staticmethod
    def generate_password(context: List[str], length: int = 15, upper_case: bool = True, lower_case: bool = True, numbers: bool = True, symbols: bool = True, exclude_similar: bool = False) -> str:
        """Generate a password based on the given parameters and context."""
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
                [PasswordGenerator.similar_chars.get(ch, ch) for ch in password_str])

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

    FILE = os.getcwd() + "\\.passwords\\passwords.epm"

    def __init__(self, password) -> None:
        self.PASSWORDS: Dict[str, Dict[str, str]] = {}
        self.VERIFIED_PASSWORD = password

    def load(self):
        """Load the passwords from the storage file."""
        with open(Storage.FILE, "rb") as file:
            data = CryptoHandler.decrypt(file.read(), self.VERIFIED_PASSWORD)
            self.PASSWORDS = data["passwords"]
            self.VERIFIED_PASSWORD = data["verified_password"]

    def save(self):
        """Save the passwords to the storage file."""
        with open(Storage.FILE, "wb") as file:
            file.write(CryptoHandler.encrypt({
                "passwords": self.PASSWORDS,
                "verified_password": self.VERIFIED_PASSWORD
            }, self.VERIFIED_PASSWORD))


class PasswordManager:

    def __init__(self, name) -> None:
        self.APP = name
        self.console = Console()

        if not os.path.exists(Storage.FILE):
            status, self.storage = self.init_pm()
        else:
            status, self.storage = self.login()

        if status:
            self.main_menu()
        else:
            sleep(1)
            self.clear_console()

    def init_pm(self):
        try:
            self.clear_console()
            self.console.print(
                "[bold green]Welcome to the Password Manager[/bold green]")
            os.makedirs(os.path.dirname(Storage.FILE), exist_ok=True)
            VERIFIED_PASSWORD = None
            while not VERIFIED_PASSWORD:
                mpass = Prompt.ask("Set a Master Password", password=True)
                mconf = Prompt.ask(
                    "Confirm the Master Password", password=True)
                if mpass == mconf:
                    VERIFIED_PASSWORD = mpass
                else:
                    self.console.print(
                        "[bold red]Passwords do not match. Try again.[/bold red]")
            storage = Storage(VERIFIED_PASSWORD)
            storage.save()
            return True, storage
        except Exception as e:
            self.console.print(
                f"[bold red]Error occurred while initializing the Password Manager: {e}[/bold red]")
            return False, None

    def clear_console(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def login(self):
        """Login to access the password manager"""
        self.clear_console()
        self.console.print(
            "[bold green]Welcome to the Password Manager[/bold green]")
        password = Prompt.ask("Enter your Master Password", password=True)

        storage = Storage(password)

        try:
            storage.load()
        except Exception as e:
            self.console.print(
                f"[bold red]Invalid password! Access denied.[/bold red]")
            return False, None

        if password == storage.VERIFIED_PASSWORD:
            self.console.print("[bold green]Login successful![/bold green]")
            sleep(1)
            self.clear_console()
            return True, storage
        else:
            self.console.print(
                "[bold red]Invalid password! Access denied.[/bold red]")
            return False, None

    def main_menu(self):
        while True:
            self.clear_console()
            self.console.print("[bold blue]Main Menu[/bold blue]")
            option = inquirer.select(
                message="Choose an option:",
                choices=[
                    "Add Password",
                    "View Password",
                    "Remove Password",
                    "Edit Password",
                    "List All",
                    "Change Master Password",
                    "Exit"
                ],
            ).execute()

            if option == "Add Password":
                self.clear_console()
                self.add_password()
            elif option == "View Password":
                self.clear_console()
                self.view_password()
            elif option == "Remove Password":
                self.clear_console()
                self.remove_password()
            elif option == "Edit Password":
                self.clear_console()
                self.edit_password()
            elif option == "List All":
                self.clear_console()
                self.list_all()
            elif option == "Change Master Password":
                self.clear_console()
                self.change_master_password()
            elif option == "Exit":
                self.console.print(
                    "[bold yellow]Exiting the Password Manager. Goodbye![/bold yellow]")
                sleep(1)
                self.clear_console()
                break

    def change_master_password(self):
        self.console.print("[bold blue]Change Master Password[/bold blue]")
        old_password = Prompt.ask(
            "Enter the old Master Password", password=True)
        self.storage.load()
        if old_password == self.storage.VERIFIED_PASSWORD:
            new_password = None
            while not new_password:
                mpass = Prompt.ask(
                    "Enter the new Master Password", password=True)
                mconf = Prompt.ask(
                    "Confirm the new Master Password", password=True)
                if mpass == mconf:
                    new_password = mpass
                else:
                    self.console.print(
                        "[bold red]Passwords do not match. Try again.[/bold red]")
            self.storage.VERIFIED_PASSWORD = new_password
            self.storage.save()
            self.console.print(
                "[bold green]Master Password changed successfully![/bold green]")
        else:
            self.console.print(
                "[bold red]Incorrect Master Password! Password not changed.[/bold red]")
        sleep(1)
        self.clear_console()

    def add_password(self):
        self.console.print("[bold blue]Add Password[/bold blue]")
        site = Prompt.ask("Enter the site/application name")
        if site in self.storage.PASSWORDS:
            self.console.print(
                f"[bold red]Password for {site} already exists![/bold red]")
            sleep(1)
            self.clear_console()
            return
        username = Prompt.ask("Enter the username")
        password = self.get_password(site, username)
        self.storage.load()
        self.storage.PASSWORDS[site] = {
            "username": username,
            "password": password
        }
        self.storage.save()
        self.console.print(
            f"[bold green]Password for {site} added successfully![/bold green]")
        pyperclip.copy(password)
        self.console.print(
            f"[bold green]Password for {site} has been copied to the clipboard![/bold green]")
        sleep(1)
        self.clear_console()

    def get_password(self, site, username):
        password = None
        while not password:
            password = Prompt.ask(
                "Enter the new password (press Enter to generate random)", password=True)
            if not password:
                length = None
                while length is None:
                    try:
                        length = int(Prompt.ask(
                            "Enter the length of the password", default=15, show_default=True))
                    except ValueError:
                        print("Length must be a number.")
                        length = None
                include_upper = inquirer.confirm(
                    message="Include uppercase letters?", default=True).execute()
                include_lower = inquirer.confirm(
                    message="Include lowercase letters?", default=True).execute()
                include_numbers = inquirer.confirm(
                    message="Include numbers?", default=True).execute()
                include_symbols = inquirer.confirm(
                    message="Include symbols?", default=True).execute()
                try:
                    password = PasswordGenerator.generate_password(
                        [site, username], length, include_upper, include_lower, include_numbers, include_symbols)
                except ValueError as e:
                    self.console.print(f"[bold red]{e}[/bold red]")
                    password = None
            else:
                cpassword = Prompt.ask("Confirm the password", password=True)
                if password != cpassword:
                    self.console.print(
                        "[bold red]Passwords do not match![/bold red]")
                    password = None
        return password

    def view_password(self):
        self.console.print("[bold blue]View Password[/bold blue]")
        site = Prompt.ask("Enter the site/application name")
        mpass = Prompt.ask("Enter the Master Password", password=True)
        self.storage.load()
        if site in self.storage.PASSWORDS:
            if mpass == self.storage.VERIFIED_PASSWORD:
                pyperclip.copy(self.storage.PASSWORDS[site]['password'])
                self.console.print(
                    f"[bold green]Password for {site} has been copied to the clipboard![/bold green]")
            else:
                self.console.print(
                    "[bold red]Incorrect Master Password! Password not copied.[/bold red]")
        else:
            self.console.print(
                f"[bold red]No password found for {site}[/bold red]")
        sleep(1)
        self.clear_console()

    def remove_password(self):
        self.console.print("[bold blue]Remove Password[/bold blue]")
        site = Prompt.ask("Enter the site/application name")
        password = Prompt.ask("Enter the Master Password", password=True)
        self.storage.load()
        if site in self.storage.PASSWORDS:
            if password == self.storage.VERIFIED_PASSWORD:
                del self.storage.PASSWORDS[site]
                self.storage.save()
                self.console.print(
                    f"[bold green]Password for {site} removed successfully![/bold green]")
            else:
                self.console.print(
                    "[bold red]Incorrect Master Password! Password not removed.[/bold red]")
        else:
            self.console.print(
                f"[bold red]No password found for {site}[/bold red]")
        sleep(1)
        self.clear_console()

    def edit_password(self):
        self.console.print("[bold blue]Edit Password[/bold blue]")
        site = Prompt.ask("Enter the site/application name")
        mpass = Prompt.ask("Enter the Master Password", password=True)
        self.storage.load()
        if site in self.storage.PASSWORDS:
            if mpass == self.storage.VERIFIED_PASSWORD:
                username = Prompt.ask(
                    "Enter the new username", default=self.storage.PASSWORDS[site]['username'])
                password = self.storage.PASSWORDS[site]['password']
                cpass = inquirer.confirm(
                    message="Change the password?", default=True).execute()
                if cpass:
                    password = self.get_password(site, username)
                self.storage.PASSWORDS[site] = {
                    "username": username,
                    "password": password
                }
                self.storage.save()
                self.console.print(
                    f"[bold green]Password for {site} updated successfully![/bold green]")
                pyperclip.copy(password)
                self.console.print(
                    f"[bold green]Password for {site} has been copied to the clipboard![/bold green]")
            else:
                self.console.print(
                    "[bold red]Incorrect Master Password! Password not updated.[/bold red]")
        else:
            self.console.print(
                f"[bold red]No password found for {site}[/bold red]")
        sleep(1)
        self.clear_console()

    def list_all(self):
        self.console.print("[bold blue]List All Passwords[/bold blue]")
        password = Prompt.ask("Enter the Master Password", password=True)
        self.storage.load()
        if password == self.storage.VERIFIED_PASSWORD:
            table = Table(title="Stored Passwords")
            table.add_column("Site/Application", style="cyan", no_wrap=True)
            table.add_column("Username", style="magenta")
            for site, credentials in self.storage.PASSWORDS.items():
                table.add_row(site, credentials["username"])
            self.console.print(table)
            site = None
            while not site:
                site = Prompt.ask(
                    "\nEnter any Site/Application name to copy its password or Press Enter to return to the main menu")
                if site != "":
                    try:
                        pyperclip.copy(
                            self.storage.PASSWORDS[site]["password"])
                    except KeyError:
                        self.console.print(
                            f"[bold red]No password found for {site}[/bold red]")
                        site = None
                else:
                    self.console.print(
                        "[bold green]Returning to the Main Menu[/bold green]")
                    sleep(0.5)
                    break
        else:
            self.console.print(
                "[bold red]Incorrect Master Password! Cannot list passwords.[/bold red]")
            sleep(1)

        self.clear_console()


if __name__ == "__main__":
    try:
        PasswordManager("PM")
    except:
        pass
