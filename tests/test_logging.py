"""
pypasscrypt.logging
-------------------

A module to log messages.

Interfaces:
----------
- `ILogger`: An interface to log messages.

Classes:
-------
- `Logger`: A class to log messages.

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
    'ILogger',
    'Logger',
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    '__copyright__',
    '__status__'
]

import logging
from abc import ABC, abstractmethod


class ILogger(ABC):
    """
    pypasscrypt.logging.ILogger
    ---------------------------

    An interface to log messages.
    
    Methods:
    --------
    - `info()`: Log an info message.
    - `warning()`: Log a warning message.
    - `error()`: Log an error message.

    Supported Classes:
    ------------------
    - `Logger`

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """
    
    @staticmethod
    @abstractmethod
    def info(message: str) -> None:
        """
        pypasscrypt.logging.ILogger.info
        --------------------------------

        Log an info message.

        :param message: The message.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def warning(message: str) -> None:
        """
        pypasscrypt.logging.ILogger.warning
        -----------------------------------

        Log a warning message.

        :param message: The message.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def error(message: str) -> None:
        """
        pypasscrypt.logging.ILogger.error
        ---------------------------------

        Log an error message.

        :param message: The message.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class Logger(ILogger):
    """
    pypasscrypt.logging.Logger
    --------------------------

    A class to log messages.
    
    Methods:
    --------
    - `init()`: Initialize the logger.
    - `info()`: Log an info message.
    - `warning()`: Log a warning message.
    - `error()`: Log an error message.

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
        pypasscrypt.logging.Logger.init
        --------------------------------

        Initialize the logger.
        
        :param log_file: The log file.
        :param log_level: The log level.
        :param log_format: The log format.
        
        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        logging.basicConfig(
            filename=log_file,
            level=log_level,
            format=log_format
        )

    @staticmethod
    def info(message: str) -> None:
        """
        pypasscrypt.logging.Logger.info
        --------------------------------

        Log an info message.
        
        :param message: The message.
        :return: None
        
        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        logging.info(message)

    @staticmethod
    def warning(message: str) -> None:
        """
        pypasscrypt.logging.Logger.warning
        -----------------------------------

        Log a warning message.
        
        :param message: The message.
        :return: None
        
        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        logging.warning(message)

    @staticmethod
    def error(message: str) -> None:
        """
        pypasscrypt.logging.Logger.error
        --------------------------------
        
        Log an error message.
        
        :param message: The message.
        :return: None
        
        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        logging.error(message)
