"""
pypasscrypt.logging
-------------------

A module to log messages.

Interfaces:
----------
- `ILoggerHandler`: An interface to log messages.

Types:
-----
- `LoggerTypes`: A literal type to specify the logger type.

Classes:
-------
- `LoggerHandler`: A class to handle the logger.

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
    'LoggerTypes',
    'ILoggerHandler',
    'LoggerHandler',
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    '__copyright__',
    '__status__'
]

import logging
from abc import ABC, abstractmethod
from typing import Literal, get_args


class ILoggerHandler(ABC):
    """
    pypasscrypt.logging.ILoggerHandler
    ---------------------------

    An interface to log messages.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    Methods:
    --------
    - `info()`: Log an info message.
    - `warning()`: Log a warning message.
    - `error()`: Log an error message.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported Classes:
    ------------------
    - `PassCryptLogger`

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    @abstractmethod
    def init(
            *,
            log_file: str,
            log_level: int,
            log_format: str
    ) -> None:
        """
        pypasscrypt.logging.ILoggerHandler.init
        --------------------------------

        Initialize the logger.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `log_file`: The log file.
        - `log_level`: The log level.
        - `log_format`: The log format.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If parameters are not of the correct type.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass
    
    @staticmethod
    @abstractmethod
    def info(*, message: str) -> None:
        """
        pypasscrypt.logging.ILoggerHandler.info
        --------------------------------

        Log an info message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        Parameters:
        -----------
        - `message`: The message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the message is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def warning(*, message: str) -> None:
        """
        pypasscrypt.logging.ILoggerHandler.warning
        -----------------------------------

        Log a warning message.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the message is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def error(*, message: str) -> None:
        """
        pypasscrypt.logging.ILoggerHandler.error
        ---------------------------------

        Log an error message.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the message is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class PassCryptLogger(ILoggerHandler):
    """
    pypasscrypt.logging.PassCryptLogger
    --------------------------

    A class to log messages.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    Methods:
    --------
    - `init()`: Initialize the logger.
    - `info()`: Log an info message.
    - `warning()`: Log a warning message.
    - `error()`: Log an error message.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def init(
            *,
            log_file: str,
            log_level: int,
            log_format: str
    ) -> None:
        """
        pypasscrypt.logging.PassCryptLogger.init
        --------------------------------

        Initialize the logger.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `log_file`: The log file.
        - `log_level`: The log level.
        - `log_format`: The log format.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If parameters are not of the correct type.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        logging.basicConfig(
            filename=log_file,
            level=log_level,
            format=log_format
        )

    @staticmethod
    def info(*, message: str) -> None:
        """
        pypasscrypt.logging.PassCryptLogger.info
        --------------------------------

        Log an info message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        Parameters:
        -----------
        - `message`: The message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the message is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        logging.info(message)

    @staticmethod
    def warning(*, message: str) -> None:
        """
        pypasscrypt.logging.PassCryptLogger.warning
        --------------------------------

        Log an warning message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        Parameters:
        -----------
        - `message`: The message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the message is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        logging.warning(message)

    @staticmethod
    def error(*, message: str) -> None:
        """
        pypasscrypt.logging.PassCryptLogger.error
        --------------------------------

        Log an error message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        Parameters:
        -----------
        - `message`: The message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the message is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        logging.error(message)


LoggerTypes = Literal['PassCryptLogger']
"""
# pypasscrypt.logging.LoggerTypes

A literal type to specify the logger type.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Values:
-------
- `PassCryptLogger`

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
"""


class LoggerHandler:
    """
    pypasscrypt.logging.LoggerHandler
    ----------------------------

    A class to handle the logger.
    
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported Types:
    ----------------
    - `PassCryptLogger`

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Methods:
    --------
    - `init()`: Initialize the logger.
    - `info()`: Log an info message.
    - `warning()`: Log a warning message.
    - `error()`: Log an error message.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def init(
            *,
            log_file: str,
            log_level: int,
            log_format: str,
            logger_type: LoggerTypes
    ) -> None:
        """
        pypasscrypt.logging.LoggerHandler.init
        --------------------------------

        Initialize the logger.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `log_file`: The log file.
        - `log_level`: The log level.
        - `log_format`: The log format.
        - `logger_type`: The logger type.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If parameters are not of the correct type.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not isinstance(log_file, str):
            raise TypeError('log_file must be a string')
        
        if not isinstance(log_level, int):
            raise TypeError('log_level must be an integer')
        
        if not isinstance(log_format, str):
            raise TypeError('log_format must be a string')
        
        if logger_type not in get_args(LoggerTypes):
            raise TypeError('logger_type must be a LoggerTypes')
        
        if logger_type == 'PassCryptLogger':
            PassCryptLogger.init(
                log_file=log_file,
                log_level=log_level,
                log_format=log_format
            )

    @staticmethod
    def info(*, message: str, logger_type: LoggerTypes) -> None:
        """
        pypasscrypt.logging.LoggerHandler.info
        --------------------------------

        Log an info message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        Parameters:
        -----------
        - `message`: The message.
        - `logger_type`: The logger type.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the message is not a string.
        - `TypeError`: If the logger_type is not a LoggerTypes.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not isinstance(message, str):
            raise TypeError('message must be a string')
        
        if logger_type not in get_args(LoggerTypes):
            raise TypeError('logger_type must be a LoggerTypes')
        
        if logger_type == 'PassCryptLogger':
            PassCryptLogger.info(message=message)

    @staticmethod
    def warning(*, message: str, logger_type: LoggerTypes) -> None:
        """
        pypasscrypt.logging.LoggerHandler.warning
        --------------------------------

        Log a warning message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        Parameters:
        -----------
        - `message`: The message.
        - `logger_type`: The logger type.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the message is not a string.
        - `TypeError`: If the logger_type is not a LoggerTypes.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not isinstance(message, str):
            raise TypeError('message must be a string')
        
        if logger_type not in get_args(LoggerTypes):
            raise TypeError('logger_type must be a LoggerTypes')
        
        if logger_type == 'PassCryptLogger':
            PassCryptLogger.warning(message=message)

    @staticmethod
    def error(*, message: str, logger_type: LoggerTypes) -> None:
        """
        pypasscrypt.logging.LoggerHandler.error
        --------------------------------

        Log an error message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        Parameters:
        -----------
        - `message`: The message.
        - `logger_type`: The logger type.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the message is not a string.
        - `TypeError`: If the logger_type is not a LoggerTypes.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if not isinstance(message, str):
            raise TypeError('message must be a string')
        
        if logger_type not in get_args(LoggerTypes):
            raise TypeError('logger_type must be a LoggerTypes')
        
        if logger_type == 'PassCryptLogger':
            PassCryptLogger.error(message=message)
