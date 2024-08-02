"""
pypasscrypt.connection
----------------------

A module for connection protocols.

Interfaces:
----------
- `IConnectionProtocol`: An interface for connection protocol classes.

Classes:
-------
- `PassCryptConnectionProtocol`: A class for the PassCrypt connection protocol.

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
    'PassCryptConnectionProtocol',
    'IConnectionProtocol',
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
    get_args
)
from pypasscrypt.cryptohandler import (
    AsymmetricEncryptionTypes,
    AsymmetricCryptoHandler
)


class IConnectionProtocol(ABC):
    """
    pypasscrypt.connection.IConnectionProtocol
    -----------------------------------------

    An interface for connection protocol classes.

    Methods:
    -------
    - `encode_connection_code()`: Create a connection code.
    - `decode_connection_code()`: Decode a connection code.
    - `request_data()`: Create a host and generate keys for receiving data.
    - `receive_data()`: Receive data from a sender.

    Supported Classes:
    ------------------
    - `PassCryptConnectionProtocol`

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
        pypasscrypt.connection.IConnectionProtocol.encode_connection_code
        ------------------------------------------------------------------

        Create a connection code.

        :param ip: The IP address.
        :param port: The port number.
        :return: The connection code.

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
        pypasscrypt.connection.IConnectionProtocol.decode_connection_code
        ------------------------------------------------------------------

        Decode a connection code.

        :param encoded_connection_code: The encoded connection code.
        :return: The IP address and port number.

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
        pypasscrypt.connection.IConnectionProtocol.request_data
        -------------------------------------------------------

        Send data to the server.

        :param ip: The IP address.
        :param port: The port number.
        :param asymmetric_encryption_type: The asymmetric encryption type.
        :return: The connection code and the sender details.

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
        pypasscrypt.connection.IConnectionProtocol.receive_data
        -------------------------------------------------------

        Send data to the server.

        :param sender_details: The sender details returned by request_data.
        :param asymmetric_encryption_type: The asymmetric encryption type.
        :return: The data received.

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
        pypasscrypt.connection.IConnectionProtocol.send_data
        ----------------------------------------------------

        Share data with another user.

        :param listings: The list of sites and usernames to share.
        :param connection_code: The connection code.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class PassCryptConnectionProtocol(IConnectionProtocol):
    """
    pypasscrypt.connection.PassCryptConnectionProtocol
    --------------------------------------------------

    A class for the PassCrypt connection protocol.

    Methods:
    -------
    - `encode_connection_code()`: Create a connection code.
    - `decode_connection_code()`: Decode a connection code.
    - `request_data()`: Create a host and generate keys for receiving data.
    - `receive_data()`: Receive data from a sender.
    - `send_data()`: Send data to a receiver.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @staticmethod
    def encode_connection_code(
            *,
            ip: str,
            port: int
    ) -> str:
        """
        pypasscrypt.connection.PassCryptConnectionProtocol.encode_connection_code
        --------------------------------------------------------------------------

        Create a connection code.

        :param ip: The IP address.
        :param port: The port number.
        :return: The connection code.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        # Pack IP address and port into bytes
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
        pypasscrypt.connection.PassCryptConnectionProtocol.decode_connection_code
        --------------------------------------------------------------------------

        Decode a connection code.

        :param encoded_connection_code: The encoded connection code.
        :return: The IP address and port number.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        # Decode from Base64 and split into IP and port
        decoded = urlsafe_b64decode(encoded_connection_code.encode())
        ip = inet_ntoa(decoded[:4])
        port = int.from_bytes(decoded[4:], byteorder='big')
        return ip, port

    @staticmethod
    def request_data(
            *,
            ip: str,
            port: int,
            asymmetric_encryption_type: AsymmetricEncryptionTypes
    ) -> Tuple[str, Tuple[socket, bytes, bytes]]:
        """
        pypasscrypt.connection.PassCryptConnectionProtocol.request_data
        -----------------------------------------------------------------

        Send data to the server.

        :param ip: The IP address.
        :param port: The port number.
        :param asymmetric_encryption_type: The asymmetric encryption type.
        :return: The connection code and the sender details.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
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

        connection_code: str = PassCryptConnectionProtocol.encode_connection_code(
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
        pypasscrypt.connection.PassCryptConnectionProtocol.receive_data
        ---------------------------------------------------------------

        Send data to the server.

        :param sender_details: The sender details returned by request_data.
        :param asymmetric_encryption_type: The asymmetric encryption type.
        :return: The data received.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
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
        pypasscrypt.connection.PassCryptConnectionProtocol.send_data
        ------------------------------------------------------------

        Share data with another user.

        :param listings: The list of sites and usernames to share.
        :param connection_code: The connection code.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        client: socket = socket(AF_INET, SOCK_STREAM)

        receiver_details: Tuple[str, int] = PassCryptConnectionProtocol.decode_connection_code(
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
