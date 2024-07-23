# PassCrypt

**PassCrypt** is a comprehensive command-line tool designed to securely store, manage, and access your passwords. Built with Python, PassCrypt leverages advanced encryption techniques to ensure your data remains safe and private.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [With pip](#with-pip)
  - [With Poetry](#with-poetry)
  - [From Source](#from-source)
- [Usage](#usage)
  - [Main Menu Options](#main-menu-options)
- [Download CLI Tool](#download-cli-tool)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Features

- 🔒 **Secure Storage**: Utilizes Fernet symmetric encryption to securely store passwords.
- 🛠 **Password Generation**: Generates strong, context-aware passwords to enhance security.
- 🔄 **Import/Export Functionality**: Easily import or export your PassCrypt storage for backup or transfer.
- 🔑 **Master Password Protection**: Secures your password vault with a master password, ensuring only authorized access.
- 💻 **Cross-Platform Compatibility**: Designed to run on multiple platforms, ensuring your passwords are accessible wherever you are.

## Installation

### Prerequisites

Before installing PassCrypt, ensure you have the following:

- Python 3.7 or higher
- pip (Python package installer)
- Poetry (dependency management tool)

If you don't have Poetry installed, you can install it by following the instructions on the [official Poetry website](https://python-poetry.org/docs/#installation).

### With pip

To install PassCrypt using pip, run the following command in your terminal:

```bash
pip install pypasscrypt
```

### With Poetry

To install PassCrypt using Poetry, run the following command in your terminal:

```bash
poetry add pypasscrypt
```

### From Source

To install PassCrypt from source, follow these steps:

- Clone the PassCrypt repository:

  ```bash
  git clone https://github.com/tejus3131/passcrypt
  ```

- Navigate to the project directory:

  ```bash
  cd passcrypt
  ```

- Install the package using Poetry:

  ```bash
  poetry install
  ```

## Usage

After installing PassCrypt, you can start the application by running:

```bash
passcrypt
```

On first run, you'll be prompted to set up a master password. This password will be used to encrypt and decrypt your stored passwords, so make sure it's strong and memorable.

### Main Menu Options

1. **List All Passwords**: Displays a table of all your stored passwords.
2. **Add Password**: Add a new password with options to generate a strong password.
3. **Edit Password**: Edit an existing password entry.
4. **Remove Password**: Remove a password entry.
5. **Settings**: Access various settings such as resetting the master password, importing/exporting storage, and more.

## Download CLI Tool

For convenience, you can also download the PassCrypt CLI tool directly from the following link:
[PassCrypt CLI Tool](https://github.com/tejus3131/passcrypt/releases/download/version_1.0.0/passcrypt.exe)

## Development

To contribute to the development of PassCrypt, follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -m 'Add some feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Open a pull request.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any bugs, enhancements, or features you'd like to add. Make sure to follow the code of conduct and contribution guidelines.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
