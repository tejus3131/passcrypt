"""
# pypasscrypt.passwordmanager
---------------------------

A module for password generation and strength checking.

Interfaces:
---------
- `IPasswordManagerHandler`: An interface for password classes.

Types:
-----
- `PasswordStrength`: The strength of a password.
- `PasswordManagerTypes`: The types of password managers available.

Classes:
-------
- `PasswordManagerHandler`: A class for password generation and strength checking.

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
    'PasswordManagerTypes',
    'IPasswordManagerHandler',
    'PasswordManagerHandler',
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    '__copyright__',
    '__status__'
]


import re
import math
from abc import (
    ABC,
    abstractmethod
)
from typing import (
    List,
    Dict,
    Optional,
    Literal,
    get_args
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


PasswordStrength = Literal['VERY_WEAK', 'WEAK', 'MEDIUM', 'STRONG', 'VERY_STRONG']
"""
# pypasscrypt.passwordmanager.PasswordStrength
----------------------------------------------

The strength of a password.

~~~~~~~~~~~~~~~

Values:
-------
- `VERY_WEAK`
- `WEAK`
- `MEDIUM`
- `STRONG`
- `VERY_STRONG`

~~~~~~~~~~~~~~~

Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
"""


class IPasswordManagerHandler(ABC):
    """
    # pypasscrypt.passwordmanager.IPasswordManagerHandler
    ----------------------------------------------

    An interface for password classes.

    ~~~~~~~~~~~~~~~

    Methods:
    --------
    - `process_context()`: Process the context strings to generate a list of valid context parts.
    - `check_strength()`: Check the strength of the password.
    - `generate_password()`: Generate a password based on the given parameters and context.

    ~~~~~~~~~~~~~~~

    Supported Classes:
    ------------------
    - `PassCryptPasswordManager`

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """
    @staticmethod
    @abstractmethod
    def process_context(*, context_list: List[str], context_filters: List[str]) -> List[str]:
        """
        # pypasscrypt.passwordmanager.IPasswordManagerHandler.process_context
        ------------------------------------------------------------

        Process the context strings to generate a list of valid context parts.

        ~~~~~~~~~~~~~~~
        
        Parameters:
        -----------
        - `context_list`: The list of context strings.
        - `context_filters`: The list of context filters.

        ~~~~~~~~~~~~~~~



        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def check_strength(*, password: str, context_list: List[str], context_filters: List[str]) -> PasswordStrength:
        """
        # pypasscrypt.passwordmanager.IPasswordManagerHandler.check_strength
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
        # pypasscrypt.passwordmanager.IPasswordManagerHandler.generate_password
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


class PassCryptPasswordManager(IPasswordManagerHandler):
    """
    # pypasscrypt.passwordmanager.PassCryptPasswordManager
    ---------------------------------------------------

    A class for password generation and strength checking.

    ~~~~~~~~~~~~~~~

    Methods:
    - `process_context()`: Process the context strings to generate a list of valid context parts.
    - `check_strength()`: Check the strength of the password.
    - `generate_password()`: Generate a password based on the given parameters and context.

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    EPOCHS = 100
    """
    # pypasscrypt.passwordmanager.PassCryptPasswordManager.EPOCHS
    ----------------------------------------------------------

    The number of epochs to generate password options.

    ~~~~~~~~~~~~~~~
    
    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def process_context(*, context_list: List[str], context_filters: List[str]) -> List[str]:
        """
        # pypasscrypt.passwordmanager.PassCryptPasswordManager.process_context
        -------------------------------------------------------------------

        Process the context strings to generate a list of valid context parts.

        ~~~~~~~~~~~~~~~
        
        Parameters:
        -----------
        - `context_list`: The list of context strings.
        - `context_filters`: The list of context filters.

        ~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the context list or context filters are invalid.

        ~~~~~~~~~~~~~~~

        Returns:
        --------
        The list of valid context parts.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if isinstance(context_list, list):
            for context in context_list:
                if not isinstance(context, str):
                    raise TypeError("Invalid context list.")
        else:
            raise TypeError("Invalid context list.")
        
        if isinstance(context_filters, list):
            for context in context_filters:
                if not isinstance(context, str):
                    raise TypeError("Invalid context filters.")
        else:
            raise TypeError("Invalid context filters.")

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
        # pypasscrypt.passwordmanager.PassCryptPasswordManager.check_strength
        -------------------------------------------------------------------

        Check the strength of the password.
        
        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `password`: The password to check.
        - `context_list`: The list of context strings.
        - `context_filters`: The list of context filters.

        ~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the password, context list, or context filters are invalid.

        ~~~~~~~~~~~~~~~

        Returns:
        --------
        The strength of the password.

        ~~~~~~~~~~~~~~~        

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(password, str):
            raise TypeError("Invalid password.")
        
        if isinstance(context_list, list):
            for context in context_list:
                if not isinstance(context, str):
                    raise TypeError("Invalid context list.")
        else:
            raise TypeError("Invalid context list.")
        
        if isinstance(context_filters, list):
            for context in context_filters:
                if not isinstance(context, str):
                    raise TypeError("Invalid context filters.")
        else:
            raise TypeError("Invalid context filters.")

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
            return "VERY_WEAK"
        elif score < 2:
            return "WEAK"
        elif score < 4:
            return "MEDIUM"
        elif score < 6:
            return "STRONG"
        else:
            return "VERY_STRONG"

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
        # pypasscrypt.passwordmanager.PassCryptPasswordManager.generate_password
        -----------------------------------------------------------------------

        Generate a password based on the given parameters and context.
        
        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `context_list`: The list of context strings.
        - `context_filters`: The list of context filters.
        - `length`: The desired length of the password.
        - `upper_case_allowed`: Whether to include uppercase letters.
        - `lower_case_allowed`: Whether to include lowercase letters.
        - `digits_allowed`: Whether to include numbers.
        - `symbols_allowed`: Whether to include symbols.
        - `swipe_similar_characters`: Whether to include similar characters.
        - `similar_characters`: A dictionary of similar characters to replace.

        ~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the context list, context filters, or similar characters dictionary are invalid.
        - `ValueError`: If the length is not a positive number or no character types are allowed.

        ~~~~~~~~~~~~~~~

        Returns:
        --------
        The generated password.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if isinstance(context_list, list):
            for context in context_list:
                if not isinstance(context, str):
                    raise TypeError("Invalid context list.")
        else:
            raise TypeError("Invalid context list.")
        
        if isinstance(context_filters, list):
            for context in context_filters:
                if not isinstance(context, str):
                    raise TypeError("Invalid context filters.")
        else:
            raise TypeError("Invalid context filters.")

        if not isinstance(length, int):
            raise ValueError("Length of password must be a natural number.")

        # Check if length is a natural number
        if length <= 0:
            raise ValueError("Length of password must be a natural number.")

        if not isinstance(upper_case_allowed, bool):
            raise TypeError("Invalid upper case allowed flag.")
        
        if not isinstance(lower_case_allowed, bool):
            raise TypeError("Invalid lower case allowed flag.")
        
        if not isinstance(digits_allowed, bool):
            raise TypeError("Invalid digits allowed flag.")
        
        if not isinstance(symbols_allowed, bool):
            raise TypeError("Invalid symbols allowed flag.")
        
        if not isinstance(swipe_similar_characters, bool):
            raise TypeError("Invalid similar characters flag.")
        
        if similar_characters is not None:
            if not isinstance(similar_characters, dict):
                raise TypeError("Invalid similar characters dictionary.")
            for key, value in similar_characters.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    raise TypeError("Invalid similar characters dictionary.")

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


PasswordManagerTypes = Literal['PassCryptPasswordManager']
"""
# pypasscrypt.passwordmanager.PasswordManagerTypes
------------------------------------------------

The types of password managers available.

~~~~~~~~~~~~~~~

Values:
-------
- `PassCryptPasswordManager`

~~~~~~~~~~~~~~~

Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
"""


class PasswordManagerHandler:
    """
    # pypasscrypt.passwordmanager.PasswordManagerHandler
    --------------------------------------------------

    A class for password generation and strength checking.

    ~~~~~~~~~~~~~~~

    Supported Types:
    ----------------
    - `PassCryptPasswordManager`

    ~~~~~~~~~~~~~~~

    Methods:
    - `process_context()`: Process the context strings to generate a list of valid context parts.
    - `check_strength()`: Check the strength of the password.
    - `generate_password()`: Generate a password based on the given parameters and context.

    ~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def process_context(
        *,
        context_list: List[str],
        context_filters: List[str],
        password_manager_type: PasswordManagerTypes
    ) -> List[str]:
        """
        # pypasscrypt.passwordmanager.PasswordManagerHandler.process_context
        -----------------------------------------------------------------------

        Get the password manager based on the given type.

        ~~~~~~~~~~~~~~~

        Supported Types:
        ----------------
        - `PassCryptPasswordManager`

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `context_list`: The list of context strings.
        - `context_filters`: The list of context filters.
        - `password_manager_type`: The type of password manager to get.

        ~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If parameters are invalid.

        ~~~~~~~~~~~~~~~

        Returns:
        --------
        The list of valid context parts.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if password_manager_type not in get_args(PasswordManagerTypes):
            raise TypeError("Invalid password manager type.")
        
        if isinstance(context_list, list):
            for context in context_list:
                if not isinstance(context, str):
                    raise TypeError("Invalid context list.")
        else:
            raise TypeError("Invalid context list.")
        
        if isinstance(context_filters, list):
            for context in context_filters:
                if not isinstance(context, str):
                    raise TypeError("Invalid context filters.")
        else:
            raise TypeError("Invalid context filters.")
        
        if password_manager_type == 'PassCryptPasswordManager':
            return PassCryptPasswordManager.process_context(
                context_list=context_list,
                context_filters=context_filters
            )
        
    @staticmethod
    def check_strength(
        *,
        password: str,
        context_list: List[str],
        context_filters: List[str],
        password_manager_type: PasswordManagerTypes
    ) -> PasswordStrength:
        """
        # pypasscrypt.passwordmanager.PasswordManagerHandler.check_strength
        -----------------------------------------------------------------------

        Check the strength of the password.

        ~~~~~~~~~~~~~~~

        Supported Types:
        ----------------
        - `PassCryptPasswordManager`

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `password`: The password to check.
        - `context_list`: The list of context strings.
        - `context_filters`: The list of context filters.
        - `password_manager_type`: The type of password manager to get.

        ~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If parameters are invalid.

        ~~~~~~~~~~~~~~~

        Returns:
        --------
        The strength of the password.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if password_manager_type not in get_args(PasswordManagerTypes):
            raise TypeError("Invalid password manager type.")
        
        if not isinstance(password, str):
            raise TypeError("Invalid password.")
        
        if isinstance(context_list, list):
            for context in context_list:
                if not isinstance(context, str):
                    raise TypeError("Invalid context list.")
        else:
            raise TypeError("Invalid context list.")
        
        if isinstance(context_filters, list):
            for context in context_filters:
                if not isinstance(context, str):
                    raise TypeError("Invalid context filters.")
        else:
            raise TypeError("Invalid context filters.")
        
        if password_manager_type == 'PassCryptPasswordManager':
            return PassCryptPasswordManager.check_strength(
                password=password,
                context_list=context_list,
                context_filters=context_filters
            )
        
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
        similar_characters: Optional[Dict[str, str]],
        password_manager_type: PasswordManagerTypes
    ) -> str:
        """
        # pypasscrypt.passwordmanager.PasswordManagerHandler.generate_password
        -----------------------------------------------------------------------

        Generate a password based on the given parameters and context.

        ~~~~~~~~~~~~~~~

        Supported Types:
        ----------------
        - `PassCryptPasswordManager`

        ~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `context_list`: The list of context strings.
        - `context_filters`: The list of context filters.
        - `length`: The desired length of the password.
        - `upper_case_allowed`: Whether to include uppercase letters.
        - `lower_case_allowed`: Whether to include lowercase letters.
        - `digits_allowed`: Whether to include numbers.
        - `symbols_allowed`: Whether to include symbols.
        - `swipe_similar_characters`: Whether to include similar characters.
        - `similar_characters`: A dictionary of similar characters to replace.
        - `password_manager_type`: The type of password manager to get.

        ~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If parameters are invalid.

        ~~~~~~~~~~~~~~~

        Returns:
        --------
        The generated password.

        ~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if password_manager_type not in get_args(PasswordManagerTypes):
            raise TypeError("Invalid password manager type.")
        
        if isinstance(context_list, list):
            for context in context_list:
                if not isinstance(context, str):
                    raise TypeError("Invalid context list.")
        else:
            raise TypeError("Invalid context list.")
        
        if isinstance(context_filters, list):
            for context in context_filters:
                if not isinstance(context, str):
                    raise TypeError("Invalid context filters.")
        else:
            raise TypeError("Invalid context filters.")
        
        if not isinstance(length, int):
            raise ValueError("Length of password must be a natural number.")
        
        if length <= 0:
            raise ValueError("Length of password must be a natural number.")
        
        if not isinstance(upper_case_allowed, bool):
            raise TypeError("Invalid upper case allowed flag.")
        
        if not isinstance(lower_case_allowed, bool):
            raise TypeError("Invalid lower case allowed flag.")
        
        if not isinstance(digits_allowed, bool):
            raise TypeError("Invalid digits allowed flag.")
        
        if not isinstance(symbols_allowed, bool):
            raise TypeError("Invalid symbols allowed flag.")
        
        if not isinstance(swipe_similar_characters, bool):
            raise TypeError("Invalid similar characters flag.")
        
        if similar_characters is not None:
            if not isinstance(similar_characters, dict):
                raise TypeError("Invalid similar characters dictionary.")
            for key, value in similar_characters.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    raise TypeError("Invalid similar characters dictionary.")
        
        if password_manager_type == 'PassCryptPasswordManager':
            return PassCryptPasswordManager.generate_password(
                context_list=context_list,
                context_filters=context_filters,
                length=length,
                upper_case_allowed=upper_case_allowed,
                lower_case_allowed=lower_case_allowed,
                digits_allowed=digits_allowed,
                symbols_allowed=symbols_allowed,
                swipe_similar_characters=swipe_similar_characters,
                similar_characters=similar_characters
            )
