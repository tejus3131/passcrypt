"""
# pypasscrypt.connection
----------------------

A module for connection protocols.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Interfaces:
----------
- `IConnectionProtocolHandler`: An interface for connection protocol classes.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Classes:
-------
- `PassCryptConnectionProtocolHandler`: A class for the PassCrypt connection protocol.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
    'ConnectionProtocolTypes',
    'IConnectionProtocolHandler',
    'ConnectionProtocolHandler',
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    '__status__'
]

from socket import (
    socket,
    AF_INET,
    SOCK_STREAM,
    inet_aton,
    inet_ntoa
)
from base64 import (
    urlsafe_b64decode,
    urlsafe_b64encode
)
from abc import (
    ABC,
    abstractmethod
)
from typing import (
    Dict,
    Optional,
    Tuple,
    Union,
    Literal,
    get_args
)
from pypasscrypt.cryptohandler import (
    AsymmetricCryptoHandler,
    AsymmetricEncryptionTypes
)


class IConnectionProtocolHandler(ABC):
    """
    # pypasscrypt.connection.IConnectionProtocolHandler
    -----------------------------------------

    An interface for connection protocol classes.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Methods:
    -------
    - `encode_connection_code()`: Create a connection code.
    - `decode_connection_code()`: Decode a connection code.
    - `request_data()`: Create a host and generate keys for receiving data.
    - `receive_data()`: Receive data from a sender.
    - `send_data()`: Send data to a receiver.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported Classes:
    ------------------
    - `PassCryptConnectionProtocolHandler`

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    @abstractmethod
    def encode_connection_code(
            *,
            ip: str,
            port: int
    ) -> str:
        """
        # pypasscrypt.connection.IConnectionProtocolHandler.encode_connection_code
        ------------------------------------------------------------------

        Create a connection code.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ip`: The IP address.
        - `port`: The port number.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the ip or port number is invalid.
        - `ValueError`: If the ip or port number is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        -------
        The connection code.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def decode_connection_code(
            *,
            encoded_connection_code: str
    ) -> Tuple[str, int]:
        """
        # pypasscrypt.connection.IConnectionProtocolHandler.decode_connection_code
        ------------------------------------------------------------------
        
        Decode a connection code.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `encoded_connection_code`: The encoded connection code.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the connection code number is invalid.
        - `ValueError`: If the connection code number is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        -------
        The IP address and port number.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def request_data(
            *,
            ip: str,
            port: int,
            asymmetric_encryption_type: AsymmetricEncryptionTypes
    ) -> Tuple[str, Tuple[socket, bytes, bytes]]:
        """
        # pypasscrypt.connection.IConnectionProtocolHandler.request_data
        -------------------------------------------------------
        
        Send data to the server.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ip`: The IP address.
        - `port`: The port number.
        - `asymmetric_encryption_type`: The asymmetric encryption type.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the ip, port or encryption type number is invalid.
        - `ValueError`: If the ip, port or encryption type number is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        -------
        The connection code and the sender details.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def receive_data(
            *,
            sender_details: Tuple[socket, bytes, bytes],
            asymmetric_encryption_type: AsymmetricEncryptionTypes
    ) -> Dict[str, Dict[str, str]]:
        """
        # pypasscrypt.connection.IConnectionProtocolHandler.receive_data
        -------------------------------------------------------

        Send data to the server.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `sender_details`: The sender details returned by request_data.
        - `asymmetric_encryption_type`: The asymmetric encryption type.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the sender's details or encryption type is invalid.
        - `ValueError`: If the sender's details or encryption type is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        -------
        The data received.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @staticmethod
    @abstractmethod
    def send_data(
            *,
            listings: Dict[str, Dict[str, str]],
            connection_code: str
    ) -> None:
        """
        # pypasscrypt.connection.IConnectionProtocolHandler.send_data
        ----------------------------------------------------

        Share data with another user.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `listings`: The list of sites and usernames to share.
        - `connection_code`: The connection code.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the listings or connection code is invalid.
        - `ValueError`: If receiver's details are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class PassCryptConnectionProtocolHandler(IConnectionProtocolHandler):
    """
    # pypasscrypt.connection.PassCryptConnectionProtocolHandler
    --------------------------------------------------

    A class for the PassCrypt connection protocol.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Methods:
    -------
    - `encode_connection_code()`: Create a connection code.
    - `decode_connection_code()`: Decode a connection code.
    - `request_data()`: Create a host and generate keys for receiving data.
    - `receive_data()`: Receive data from a sender.
    - `send_data()`: Send data to a receiver.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def encode_connection_code(
            *,
            ip: str,
            port: int
    ) -> str:
        """
        # pypasscrypt.connection.PassCryptConnectionProtocolHandler.encode_connection_code
        --------------------------------------------------------------------------

        Create a connection code.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ip`: The IP address.
        - `port`: The port number.  

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the ip or port number is invalid.
        - `ValueError`: If the ip or port number is invalid.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        -------
        The connection code.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        # Pack IP address and port into bytes
        
        if not isinstance(ip, str):
            raise TypeError('ip must be a string')
        else:
            if len(ip.split('.')) != 4:
                raise ValueError('Invalid IP address')
            
            for i in ip.split('.'):
                if not i.isdigit():
                    raise ValueError('Invalid IP address')
                if int(i) < 0 or int(i) > 255:
                    raise ValueError('Invalid IP address')
        
        if not isinstance(port, int):
            raise TypeError('port must be an integer')
        else:
            if port < 0 or port > 65535:
                raise ValueError('Invalid port number')

        packed_ip = inet_aton(ip)
        packed_port = port.to_bytes(2, byteorder='big')
        # Combine and encode in Base64
        encoded = urlsafe_b64encode(packed_ip + packed_port).decode()
        return encoded

    @staticmethod
    def decode_connection_code(
            *,
            encoded_connection_code: str
    ) -> Tuple[str, int]:
        """
        # pypasscrypt.connection.PassCryptConnectionProtocolHandler.decode_connection_code
        --------------------------------------------------------------------------

        Decode a connection code.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `encoded_connection_code`: The encoded connection code.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        Raises:
        -------
        - `TypeError`: If the connection code number is invalid.
        - `ValueError`: If the connection code number is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        -------
        The IP address and port number.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(encoded_connection_code, str):
            raise TypeError('encoded_connection_code must be a string')
        
        # Decode from Base64 and split into IP and port
        try:
            decoded = urlsafe_b64decode(encoded_connection_code.encode())
            ip = inet_ntoa(decoded[:4])
            port = int.from_bytes(decoded[4:], byteorder='big')
        except Exception as e:
            raise ValueError('Invalid connection code') from e
        
        return ip, port

    @staticmethod
    def request_data(
            *,
            ip: str,
            port: int,
            asymmetric_encryption_type: AsymmetricEncryptionTypes
    ) -> Tuple[str, Tuple[socket, bytes, bytes]]:
        """
        # pypasscrypt.connection.PassCryptConnectionProtocolHandler.request_data
        -----------------------------------------------------------------

        Send data to the server.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ip`: The IP address.
        - `port`: The port number.
        - `asymmetric_encryption_type`: The asymmetric encryption type.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the ip, port or encryption type number is invalid.
        - `ValueError`: If the ip, port or encryption type number is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        -------
        The connection code and the sender details.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        
        if not isinstance(ip, str):
            raise TypeError('ip must be a string')
        else:
            if len(ip.split('.')) != 4:
                raise ValueError('Invalid IP address')
            
            for i in ip.split('.'):
                if not i.isdigit():
                    raise ValueError('Invalid IP address')
                if int(i) < 0 or int(i) > 255:
                    raise ValueError('Invalid IP address')
        
        if not isinstance(port, int):
            raise TypeError('port must be an integer')
        else:
            if port < 0 or port > 65535:
                raise ValueError('Invalid port number')
            
        if asymmetric_encryption_type not in get_args(AsymmetricEncryptionTypes):
            raise TypeError('asymmetric_encryption_type must be an AsymmetricEncryptionTypes')
            
        # Create a socket object
        host: socket = socket(AF_INET, SOCK_STREAM)
        while True:
            try:
                host.bind((ip, port))
                break
            except ConnectionRefusedError:
                port += 1
        host.listen(1)

        data: Tuple[bytes, bytes] = AsymmetricCryptoHandler.generate_keys(
            method=asymmetric_encryption_type
        )
        private_key_pem: bytes = data[0]
        public_key_pem: bytes = data[1]

        connection_code: str = PassCryptConnectionProtocolHandler.encode_connection_code(
            ip=ip,
            port=port
        )

        return connection_code, (host, private_key_pem, public_key_pem)

    @staticmethod
    def receive_data(
            *,
            sender_details: Tuple[socket, bytes, bytes],
            asymmetric_encryption_type: AsymmetricEncryptionTypes
    ) -> Dict[str, Dict[str, str]]:
        """
        # pypasscrypt.connection.PassCryptConnectionProtocolHandler.receive_data
        ---------------------------------------------------------------

        Send data to the server.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `sender_details`: The sender details returned by request_data.
        - `asymmetric_encryption_type`: The asymmetric encryption type.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the sender's details or encryption type is invalid.
        - `ValueError`: If the sender's details or encryption type is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        -------
        The data received.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(sender_details, tuple):
            raise TypeError('sender_details must be a tuple')
        else:
            if len(sender_details) != 3:
                raise ValueError('Invalid sender_details')
            if not isinstance(sender_details[0], socket):
                raise TypeError('sender_details[0] must be a socket')
            if not isinstance(sender_details[1], bytes):
                raise TypeError('sender_details[1] must be a bytes')
            if not isinstance(sender_details[2], bytes):
                raise TypeError('sender_details[2] must be a bytes')        
            
        if asymmetric_encryption_type not in get_args(AsymmetricEncryptionTypes):
            raise TypeError('asymmetric_encryption_type must be an AsymmetricEncryptionTypes')

        host: socket = sender_details[0]
        private_key_pem: bytes = sender_details[1]
        public_key_pem: bytes = sender_details[2]

        connection_details: Tuple[socket, Tuple[str, int]] = host.accept()
        connection: socket = connection_details[0]

        with connection:
            connection.sendall(
                len(public_key_pem).to_bytes(4, byteorder='big'))
            connection.sendall(public_key_pem)
            connection.sendall(asymmetric_encryption_type.encode())
            length: int = int.from_bytes(connection.recv(4), byteorder='big')
            encrypted_data: bytes = b''
            while len(encrypted_data) < length:
                encrypted_data += connection.recv(1024)

            json_data: Dict[str, Dict[str, str]] = AsymmetricCryptoHandler.decrypt(
                encrypted_data=encrypted_data,
                private_key_pem=private_key_pem,
                method=asymmetric_encryption_type
            )

        return json_data

    @staticmethod
    def send_data(
            *,
            listings: Dict[str, Dict[str, str]],
            connection_code: str
    ) -> None:
        """
        # pypasscrypt.connection.PassCryptConnectionProtocolHandler.send_data
        ------------------------------------------------------------

        Share data with another user.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `listings`: The list of sites and usernames to share.
        - `connection_code`: The connection code.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the listings or connection code is invalid.
        - `ValueError`: If receiver's details are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(listings, dict):
            raise TypeError("Invalid listings")
        else:
            for key, value in listings.items():
                if not isinstance(key, str):
                    raise TypeError("Invalid listings")
                if not isinstance(value, dict):
                    raise TypeError("Invalid listings")
                for k, v in value.items():
                    if not isinstance(k, str):
                        raise TypeError("Invalid listings")
                    if not isinstance(v, str):
                        raise TypeError("Invalid listings")
                    
        if not isinstance(connection_code, str):
            raise TypeError('connection_code must be a string')

        client: socket = socket(AF_INET, SOCK_STREAM)

        receiver_details: Tuple[str, int] = PassCryptConnectionProtocolHandler.decode_connection_code(
            encoded_connection_code=connection_code
        )
        ip: str = receiver_details[0]
        port: int = receiver_details[1]

        client.connect((ip, port))

        public_key_pem_length: int = int.from_bytes(
            client.recv(4), byteorder='big')
        public_key_pem: bytes = b''
        while len(public_key_pem) < public_key_pem_length:
            public_key_pem += client.recv(1024)

        data: Union[str, AsymmetricEncryptionTypes] = client.recv(
            1024).decode()
        asymmetric_encryption_type: Optional[AsymmetricEncryptionTypes] = None

        if data in get_args(AsymmetricEncryptionTypes):
            for option in get_args(AsymmetricEncryptionTypes):
                if data == option:
                    asymmetric_encryption_type = option
                    break
        else:
            raise ValueError('Invalid asymmetric encryption type')

        if not asymmetric_encryption_type:
            raise ValueError('Invalid asymmetric encryption type')

        encrypted_data: bytes = AsymmetricCryptoHandler.encrypt(
            json_data=listings,
            public_key_pem=public_key_pem,
            method=asymmetric_encryption_type
        )

        length: int = len(encrypted_data)
        client.sendall(length.to_bytes(4, byteorder='big'))
        client.sendall(encrypted_data)
        client.close()


ConnectionProtocolTypes = Literal["PassCryptConnectionProtocolHandler"]
"""
# pypasscrypt.connection.ConnectionProtocolTypes
----------------------------------------------

A literal type for connection protocol classes.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Values:
-------
- `PassCryptConnectionProtocolHandler`

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
"""


class ConnectionProtocolHandler:
    """
    # pypasscrypt.connection.ConnectionProtocolHandler
    ------------------------------------------------

    A class to handle connection protocols.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    Supported Types:
    ----------------
    - `PassCryptConnectionProtocolHandler` 

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Methods:
    -------
    - `encode_connection_code()`: Create a connection code.
    - `decode_connection_code()`: Decode a connection code.
    - `request_data()`: Create a host and generate keys for receiving data.
    - `receive_data()`: Receive data from a sender.
    - `send_data()`: Send data to a receiver.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """
    
    @staticmethod
    def encode_connection_code(
            *,
            ip: str,
            port: int,
            connection_protocol: ConnectionProtocolTypes
    ) -> str:
        """
        # pypasscrypt.connection.ConnectionProtocolHandler.encode_connection_code
        ------------------------------------------------------------------------

        Create a connection code.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Supported Types:
        ----------------
        - `PassCryptConnectionProtocolHandler`

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ip`: The IP address.
        - `port`: The port number.
        - `connection_protocol`: The connection protocol.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the connection protocol is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        -------
        The connection code.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if connection_protocol not in get_args(ConnectionProtocolTypes):
            raise TypeError('Invalid connection protocol')
        
        if connection_protocol == 'PassCryptConnectionProtocolHandler':
            return PassCryptConnectionProtocolHandler.encode_connection_code(
                ip=ip,
                port=port
            )
        
    @staticmethod
    def decode_connection_code(
            *,
            encoded_connection_code: str,
            connection_protocol: ConnectionProtocolTypes
    ) -> Tuple[str, int]:
        """
        # pypasscrypt.connection.ConnectionProtocolHandler.decode_connection_code
        ------------------------------------------------------------------------

        Decode a connection code.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Supported Types:
        ----------------
        - `PassCryptConnectionProtocolHandler`

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `encoded_connection_code`: The encoded connection code.
        - `connection_protocol`: The connection protocol.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the connection protocol is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        -------
        The IP address and port number.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`,tejus3131@gmail.com>
        """
        if connection_protocol not in get_args(ConnectionProtocolTypes):
            raise TypeError('Invalid connection protocol')
        
        if connection_protocol == 'PassCryptConnectionProtocolHandler':
            return PassCryptConnectionProtocolHandler.decode_connection_code(
                encoded_connection_code=encoded_connection_code
            )
        
    @staticmethod
    def request_data(
            *,
            ip: str,
            port: int,
            asymmetric_encryption_type: AsymmetricEncryptionTypes,
            connection_protocol: ConnectionProtocolTypes
    ) -> Tuple[str, Tuple[socket, bytes, bytes]]:
        """
        # pypasscrypt.connection.ConnectionProtocolHandler.request_data
        ------------------------------------------------------------

        Send data to the server.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Supported Types:
        ----------------
        - `PassCryptConnectionProtocolHandler`

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ip`: The IP address.
        - `port`: The port number.
        - `asymmetric_encryption_type`: The asymmetric encryption type.
        - `connection_protocol`: The connection protocol.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the connection protocol is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        -------
        The connection code and the sender details.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`,tejus3131@gmail.com>
        """
        if connection_protocol not in get_args(ConnectionProtocolTypes):
            raise TypeError('Invalid connection protocol')
        
        if connection_protocol == 'PassCryptConnectionProtocolHandler':
            return PassCryptConnectionProtocolHandler.request_data(
                ip=ip,
                port=port,
                asymmetric_encryption_type=asymmetric_encryption_type
            )
        
    @staticmethod
    def receive_data(
            *,
            sender_details: Tuple[socket, bytes, bytes],
            asymmetric_encryption_type: AsymmetricEncryptionTypes,
            connection_protocol: ConnectionProtocolTypes
    ) -> Dict[str, Dict[str, str]]:
        """
        # pypasscrypt.connection.ConnectionProtocolHandler.receive_data
        ------------------------------------------------------------

        Send data to the server.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Supported Types:
        ----------------
        - `PassCryptConnectionProtocolHandler`

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `sender_details`: The sender details returned by request_data.
        - `asymmetric_encryption_type`: The asymmetric encryption type.
        - `connection_protocol`: The connection protocol.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the connection protocol is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns: 
        -------
        The data received.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if connection_protocol not in get_args(ConnectionProtocolTypes):
            raise TypeError('Invalid connection protocol')
        
        if connection_protocol == 'PassCryptConnectionProtocolHandler':
            return PassCryptConnectionProtocolHandler.receive_data(
                sender_details=sender_details,
                asymmetric_encryption_type=asymmetric_encryption_type
            )
        
    @staticmethod
    def send_data(
            *,
            listings: Dict[str, Dict[str, str]],
            connection_code: str,
            connection_protocol: ConnectionProtocolTypes
    ) -> None:
        """
        # pypasscrypt.connection.ConnectionProtocolHandler.send_data
        ----------------------------------------------------------

        Share data with another user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Supported Types:
        ----------------
        - `PassCryptConnectionProtocolHandler`

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `listings`: The list of sites and usernames to share.
        - `connection_code`: The connection code.
        - `connection_protocol`: The connection protocol.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the connection protocol is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if connection_protocol not in get_args(ConnectionProtocolTypes):
            raise TypeError('Invalid connection protocol')
        
        if connection_protocol == 'PassCryptConnectionProtocolHandler':
            return PassCryptConnectionProtocolHandler.send_data(
                listings=listings,
                connection_code=connection_code
            )
