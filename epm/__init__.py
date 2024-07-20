"""Password Manager package."""

from epm.main import PasswordManager

__all__ = ['PasswordManager']
__version__ = '0.1.0'


def main():
    PasswordManager("PM")


if __name__ == "__main__":
    main()
