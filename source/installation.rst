Installation
============

PassCrypt is a Python package for secure password management. This guide will walk you through the installation process.

Prerequisites
-------------

Before installing PassCrypt, ensure you have the following:

- Python 3.7 or higher
- pip (Python package installer)
- Poetry (dependency management tool)

If you don't have Poetry installed, you can install it by following the instructions on the `official Poetry website <https://python-poetry.org/docs/#installation>`_.

Installing PassCrypt
--------------------

1. With pip

To install PassCrypt using pip, run the following command in your terminal:

.. code-block:: bash

   pip install pypasscrypt

2. With Poetry

To install PassCrypt using Poetry, run the following command in your terminal:

.. code-block:: bash

   poetry add pypasscrypt

3. From Source

To install PassCrypt from source, follow these steps:

- Clone the PassCrypt repository:

.. code-block:: bash

   git clone

- Navigate to the project directory:

.. code-block:: bash

   cd passcrypt

- Install the package using Poetry:

.. code-block:: bash

   poetry install

You're now ready to use PassCrypt!

Verifying the Installation
--------------------------

To verify that PassCrypt has been installed correctly, you can run the following command in your terminal:

.. code-block:: bash

   python -c "import pypasscrypt"

If no errors are displayed, PassCrypt has been successfully installed.

Troubleshooting
---------------

If you encounter any issues during installation, please check the following:

1. Ensure you're using a compatible Python version (3.7+).
2. Make sure Poetry is installed correctly and up to date.
3. Check that all dependencies are installed by running ``poetry show``.

If problems persist, please open an issue on the `PassCrypt GitHub repository <https://github.com/tejus3131/passcrypt/issues>`_.

Updating PassCrypt
------------------

To update PassCrypt to the latest version, run the following commands:

1. With pip

.. code-block:: bash

   pip install --upgrade pypasscrypt

2. With Poetry

.. code-block:: bash

   poetry update

This will fetch the latest changes and update all dependencies to their latest compatible versions.