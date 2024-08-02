"""
pypasscrypt.passwordmanager
---------------------------

A module for password generation and strength checking.

Interfaces:
---------
- `IPasswordManager`: An interface for password classes.

Classes:
-------
- `PassCryptPasswordManager`: A class for password generation and strength checking.

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
    'IPasswordManager',
    'PassCryptPasswordManager',
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    '__copyright__',
    '__status__'
]


import re
import math
from enum import Enum
from abc import (
    ABC,
    abstractmethod
)
from typing import (
    List,
    Dict,
    Optional
)
from random import (
    choice,
    randint,
    sample
)
from string import (
    ascii_uppercase,
    ascii_lowercase,
    digits,
    punctuation
)


class PasswordStrength(Enum):
    """
    pypasscrypt.passwordmanager.PasswordStrength
    ---------------------------------------------

    An enumeration for password strength levels.

    Values:
    -------
    `VERY_WEAK`: Password is very weak.
    `WEAK`: Password is weak.
    `MEDIUM`: Password is medium.
    `STRONG`: Password is strong.
    `VERY_STRONG`: Password is very strong.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """
    VERY_WEAK = 1
    WEAK = 2
    MEDIUM = 3
    STRONG = 4
    VERY_STRONG = 5


class IPasswordManager(ABC):
    """
    pypasscrypt.passwordmanager.IPasswordManager
    ----------------------------------------------

    An interface for password classes.

    Methods:
    --------
    - `process_context()`: Process the context strings to generate a list of valid context parts.
    - `check_strength()`: Check the strength of the password.
    - `generate_password()`: Generate a password based on the given parameters and context.

    Supported Classes:
    ------------------
    - `PassCryptPasswordManager`

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """
    @staticmethod
    @abstractmethod
    def process_context(*, context_list: List[str], context_filters: List[str]) -> List[str]:
        """
        pypasscrypt.passwordmanager.IPasswordManager.process_context
        ------------------------------------------------------------

        Process the context strings to generate a list of valid context parts.

        :param context_list: The list of context strings.
        :param context_filters: The list of context filters.
        :return: A list of valid context parts.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def check_strength(*, password: str, context_list: List[str], context_filters: List[str]) -> PasswordStrength:
        """
        pypasscrypt.passwordmanager.IPasswordManager.check_strength
        ----------------------------------------------------------

        Check the strength of the password.

        :param password: The password to check.
        :param context_list: The list of context strings.
        :param context_filters: The list of context filters.
        :return: The strength of the password.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def generate_password(
        *,
        context_list: List[str],
        context_filters: List[str],
        length: int = 15,
        upper_case_allowed: bool = True,
        lower_case_allowed: bool = True,
        digits_allowed: bool = True,
        symbols_allowed: bool = True,
        swipe_similar_characters: bool = True,
        similar_characters: Optional[Dict[str, str]] = None
    ) -> str:
        """
        pypasscrypt.passwordmanager.IPasswordManager.generate_password
        --------------------------------------------------------------

        Generate a password based on the given parameters and context.

        :param context_list: The list of context strings.
        :param context_filters: The list of context filters.
        :param length: The desired length of the password.
        :param upper_case_allowed: Whether to include uppercase letters.
        :param lower_case_allowed: Whether to include lowercase letters.
        :param digits_allowed: Whether to include numbers.
        :param symbols_allowed: Whether to include symbols.
        :param swipe_similar_characters: Whether to include similar characters.
        :param similar_characters: A dictionary of similar characters to replace.
        :return: The generated password.
        :raises ValueError: If the length is not a positive number or no character types are allowed.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class PassCryptPasswordManager(IPasswordManager):
    """
    pypasscrypt.passwordmanager.PassCryptPasswordManager
    ---------------------------------------------------

    A class for password generation and strength checking.

    Methods:
    - `process_context()`: Process the context strings to generate a list of valid context parts.
    - `check_strength()`: Check the strength of the password.
    - `generate_password()`: Generate a password based on the given parameters and context.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    EPOCHS = 100
    """
    pypasscrypt.passwordmanager.PassCryptPasswordManager.EPOCHS
    ----------------------------------------------------------

    The number of epochs to generate password options.
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def process_context(*, context_list: List[str], context_filters: List[str]) -> List[str]:
        """
        pypasscrypt.passwordmanager.PassCryptPasswordManager.process_context
        -------------------------------------------------------------------

        Process the context strings to generate a list of valid context parts.

        :param context_list: The list of context strings.
        :param context_filters: The list of context filters.
        :return: A list of valid context parts.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        # filter context words by context filters
        context_filter: str = r'\b(' + '|'.join(context_filters) + r')\b'
        # split context words by non-alphanumeric characters
        context_pattern = r'[^\w\s]'

        valid_context: List[str] = []

        for context in context_list:
            context_parts = re.split(context_pattern, context)
            for part in context_parts:
                if not re.search(context_filter, part, re.IGNORECASE):
                    valid_context.append(part)

        return valid_context

    @staticmethod
    def check_strength(*, password: str, context_list: List[str], context_filters: List[str]) -> PasswordStrength:
        """
        pypasscrypt.passwordmanager.PassCryptPasswordManager.check_strength
        -------------------------------------------------------------------

        Check the strength of the password.

        :param password: The password to check.
        :param context_list: The list of context strings.
        :param context_filters: The list of context filters.
        :return: The strength of the password.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        score: float = 0

        # Check if password contains context filters
        for context in context_filters:
            context_pattern = r'\b' + re.escape(context) + r'\b'
            if re.search(context_pattern, password, re.IGNORECASE):
                score -= 1

        # Check if password contains context words
        for context in context_list:
            context_pattern = r'\b' + re.escape(context) + r'\b'
            if re.search(context_pattern, password, re.IGNORECASE):
                score -= 0.5

        # Length checks
        length: int = len(password)
        if length < 16:
            score -= (16 - length) / 4

        # Pattern checks for uppercase, lowercase, digits, and special characters
        patterns: List[str] = [
            r'(?=.*[A-Z])',  # At least one uppercase letter
            r'(?=.*[a-z])',  # At least one lowercase letter
            r'(?=.*\d)',     # At least one digit
            r'(?=.*[@$!%*?&])',  # At least one special character
        ]

        # Add 1 point for each pattern match
        score += sum(bool(re.search(p, password)) for p in patterns)

        # Entropy calculation based on character set size and password length
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in punctuation for c in password):
            charset_size += len(punctuation)

        if charset_size > 0:
            entropy = length * math.log2(charset_size)
        else:
            entropy = 0

        # Adjust score based on entropy value
        if entropy < 28:
            score -= 1
        elif entropy < 36:
            score += 1
        elif entropy < 60:
            score += 2
        elif entropy < 128:
            score += 3
        else:
            score += 4
        # Determine password strength based on final score
        if score < 0:
            return PasswordStrength.VERY_WEAK
        elif score < 2:
            return PasswordStrength.WEAK
        elif score < 4:
            return PasswordStrength.MEDIUM
        elif score < 6:
            return PasswordStrength.STRONG
        else:
            return PasswordStrength.VERY_STRONG

    @staticmethod
    def generate_password(
        *,
        context_list: List[str],
        context_filters: List[str],
        length: int = 15,
        upper_case_allowed: bool = True,
        lower_case_allowed: bool = True,
        digits_allowed: bool = True,
        symbols_allowed: bool = True,
        swipe_similar_characters: bool = True,
        similar_characters: Optional[Dict[str, str]] = None
    ) -> str:
        """
        pypasscrypt.passwordmanager.PassCryptPasswordManager.generate_password
        -----------------------------------------------------------------------

        Generate a password based on the given parameters and context.

        :param context_list: The list of context strings.
        :param context_filters: The list of context filters.
        :param length: The desired length of the password.
        :param upper_case_allowed: Whether to include uppercase letters.
        :param lower_case_allowed: Whether to include lowercase letters.
        :param digits_allowed: Whether to include numbers.
        :param symbols_allowed: Whether to include symbols.
        :param swipe_similar_characters: Whether to include similar characters.
        :param similar_characters: A dictionary of similar characters to replace.
        :return: The generated password.
        :raises ValueError: If the length is not a positive number or no character types are allowed.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        # Check if length is a natural number
        if length <= 0:
            raise ValueError("Length of password must be a natural number.")

        # Check if any characters are allowed
        allowed_chars = ''
        if upper_case_allowed:
            allowed_chars += ascii_uppercase
        if lower_case_allowed:
            allowed_chars += ascii_lowercase
        if digits_allowed:
            allowed_chars += digits
        if symbols_allowed:
            allowed_chars += punctuation

        # Check if any characters are allowed
        if not allowed_chars:
            raise ValueError(
                "No characters available to generate password. Ensure at least one type of character is allowed.")

        # Process context strings
        context_list = PassCryptPasswordManager.process_context(
            context_list=context_list,
            context_filters=context_filters
        )

        # Replace similar characters if required
        if swipe_similar_characters and similar_characters:
            for string in context_list:
                context_list.remove(string)
                for key, value in similar_characters.items():
                    string = string.replace(key, value)
                context_list.append(string)

        # Generate password options based on context and allowed characters
        password_options: List[str] = []
        for _ in range(PassCryptPasswordManager.EPOCHS):
            password_parts: List[str] = sample(allowed_chars, length*2)
            password_parts[randint(0, length*2 - 1)] = choice(context_list)
            password_str: str = ''.join(password_parts)
            slice_index: int = randint(0, len(password_str) - length)
            password_options.append(
                password_str[slice_index: length + slice_index])

        # Check password strength and return the strongest password
        password_strengths: Dict[str, PasswordStrength] = {}
        for password in password_options:
            password_strengths[password] = PassCryptPasswordManager.check_strength(
                password=password,
                context_list=context_list,
                context_filters=context_filters
            )
        top_passwords: List[str] = sorted(
            password_strengths,
            key=lambda x: str(password_strengths.get(x)),
            reverse=True
        )

        return top_passwords[randint(0, int(PassCryptPasswordManager.EPOCHS / 10) + 1)]
