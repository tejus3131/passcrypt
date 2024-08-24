import os
from logging import config
from time import sleep
from typing import Any, List, Optional, Tuple, get_args
from pypasscrypt import (
    # connection
    ConnectionProtocolTypes,

    # cryptohandler
    SymmetricEncryptionTypes,
    AsymmetricEncryptionTypes,
    HashTypes,

    # passwordmanager
    PasswordManagerTypes,

    # storage
    EPC,
    EPT,
    PasswordBucket,

    # userinterface
    UI,
    UINotificationDisplay,
    UINotificationDisplay,
    UIPanelDisplay,
    UITableDisplay,
    UITextInput,
    UITextSuggestionInput,
    UISingleSelectionInput,
    UIMultiSelectionInput,
    UIConfirmInput,
    UINewPasswordInput,
    UIMasterPasswordInput,
    UINewMasterPasswordInput,
    UIFileInput
)
from passcrypt_cli.config import Config
from pypasscrypt.storagehandler import InvalidEPCFileError
from pypasscrypt.connectionhandler import ConnectionProtocolHandler, InvalidConnectionProtocolError

from pyperclip import copy  # type: ignore


class PasscryptCLI:
    def __init__(self) -> None:
        self.ui: UI = UI()
        self.config: Config = Config()
        self.user: str
        self.secret: str
        self.storage: EPC

    def start(self, animate: bool) -> None:
        try:
            if animate:
                self.ui.animate(
                    message="Welcome to Passcrypt CLI",
                    title=f"Passcrypt CLI",
                    wait_time=1.0,
                    border_style="magenta"
                )

            users: List[str] = self.config.get_users()

            if len(users) == 0:
                self.setup()
            else:
                self.login(users=users)
        except KeyboardInterrupt:
            self.ui.exit(exit_message="Exiting Passcrypt CLI")
        
        self.mainloop()

    def setup(self) -> None:

        @self.ui.page(
            title=f"PassCrypt - Setup",
            subtitle="Press ctrl+c to exit",
            message="Welcome to Passcrypt CLI. This is a one-time setup process to configure your account settings."
        )
        def __setup() -> None:

            username_input = UITextInput(
                message="Create a new username"
            )
            master_password_input = UINewMasterPasswordInput()

            user = self.ui.render(component=username_input)

            if not isinstance(user, str):
                raise ValueError("Invalid username")
            else:
                self.user = user

            self.secret = self.ui.render(component=master_password_input)

            self.config.create(
                username=self.user,
                secret=self.secret
            )

            self.storage = self.config.get_storage(
                username=self.user, secret=self.secret)

            modify_input = UIConfirmInput(
                message="Do you want to modify the configuration?",
                default=False
            )

            if self.ui.render(component=modify_input):
                self.modify_config()

        __setup()

    def modify_config(self) -> None:
        @self.ui.page(
            title=f"PassCrypt - {self.user} - Modify Configuration",
            subtitle="Press ctrl+c to go to main menu",
            message="Modify your account settings, connection settings, encryption settings, and password settings."
        )
        def __modify_config() -> None:

            mutables: List[str] = ["Account Settings", "Connection Settings",
                                   "Encryption Settings", "Password Settings", "Storage Settings"]

            mutable_input = UISingleSelectionInput(
                message="Select a configuration to modify",
                choices=mutables
            )

            mutable = self.ui.render(component=mutable_input)

            if mutable == "Account Settings":
                self.modify_account_settings()

            elif mutable == "Connection Settings":
                self.modify_connection_settings()

            elif mutable == "Encryption Settings":
                self.modify_encryption_settings()

            elif mutable == "Password Settings":
                self.modify_password_settings()

            elif mutable == "Storage Settings":
                self.modify_storage_settings()
            __modify_config()

        try:
            __modify_config()
        except KeyboardInterrupt:
            pass

    def modify_account_settings(self) -> None:

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Account Settings (Changing Username)",
            subtitle="Press ctrl+c to go to settings",
            message="Change your username."
        )
        def __modify_username() -> None:
            username_input = UITextInput(
                message="Enter new username"
            )
            user = self.ui.render(component=username_input)
            if not isinstance(user, str):
                raise ValueError("Invalid username")
            else:
                self.config.change_username(
                    old_username=self.user, new_username=user)
                self.user = user

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Account Settings (Changing Master Password)",
            subtitle="Press ctrl+c to cancel",
            message="Change your master password.",
            style="error"
        )
        def __modify_master_password() -> None:
            master_password_input = UINewMasterPasswordInput()

            if not self.storage:
                self.storage = self.config.get_storage(
                    username=self.user, secret=self.secret)
                
            try:

                self.storage.change_secret(
                    new_secret=self.ui.render(component=master_password_input)
                )

                self.secret = self.storage.secret
            except Exception as e:
                print(e)
                sleep(5)
                raise e

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Account Settings(Deleting Account)",
            subtitle="Press ctrl+c to cancel",
            message="This action is irreversible. Deleting your account will delete all your passwords and settings.",
            style="error"
        )
        def __delete_account():
            confirm_input = UIConfirmInput(
                message="Do you want to delete your account?",
                default=False
            )

            if not self.ui.render(component=confirm_input):
                self.ui.render(component=UINotificationDisplay(
                    message="Account deletion cancelled",
                    style="info"
                ))
                return
            
            self.config.delete(username=self.user)
            self.ui.render(component=UINotificationDisplay(
                message="Account deleted successfully",
                style="success"
            ))
            self.start(animate=False)
            exit(code=0)

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Account Settings",
            subtitle="Press ctrl+c to cancel",
            message="Change your username and master password."
        )
        def __modify_account_settings() -> None:

            account_settings = UISingleSelectionInput(
                message="Select an account setting to modify",
                choices=["Change Username", "Change Master Password", 'Delete Account'],
                skip_message="Cancel"
            )

            account_setting = self.ui.render(component=account_settings)

            if not account_setting:
                return

            try:
                if account_setting == "Change Username":
                    __modify_username()

                elif account_setting == "Change Master Password":
                    __modify_master_password()

                elif account_setting == "Delete Account":
                    __delete_account()

            except KeyboardInterrupt:
                pass
            finally:
                __modify_account_settings()

        try:
            __modify_account_settings()
        except KeyboardInterrupt:
            pass
        finally:
            self.modify_config()

    def modify_connection_settings(self) -> None:
        @self.ui.page(
            title=f"PassCrypt - {self.user} - Connection Settings(Changing Connection Port)",
            subtitle="Press ctrl+c to cancel",
            message="Change your default connection port."
        )
        def __modify_connection_port() -> None:
            connection_port_input = UITextInput(
                message="Enter a new connection port",
                default=str(self.config.read(username=self.user).DEFAULT_PORT)
            )
            new_port: int = 0

            while new_port == 0:
                connection_port: str = self.ui.render(
                    component=connection_port_input)
                if not isinstance(connection_port, str):
                    raise ValueError("Invalid connection port")
                else:
                    try:
                        new_port = int(connection_port)
                    except ValueError:
                        new_port = 0
                        self.ui.render(component=UINotificationDisplay(
                            message="Invalid port number",
                            style="error"
                        ))

            self.config.update(
                key="DEFAULT_PORT",
                value=new_port,
                username=self.user
            )

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Connection Settings(Changing Connection Protocol)",
            subtitle="Press ctrl+c to cancel",
            message="Change your default connection protocol."
        )
        def __modify_connection_protocol() -> None:
            connection_protocol_input = UISingleSelectionInput(
                message="Select a connection protocol",
                choices=list(get_args(ConnectionProtocolTypes)),
                skip_message="Cancel",
                default=str(self.config.read(
                    username=self.user).CONNECTION_PROTOCOL)
            )

            connection_protocol: ConnectionProtocolTypes = self.ui.render(
                component=connection_protocol_input)

            if not connection_protocol:
                return

            self.config.update(
                key="CONNECTION_PROTOCOL",
                value=connection_protocol,
                username=self.user
            )

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Connection Settings",
            subtitle="Press ctrl+c to go to main menu",
            message="Change your default connection port and protocol."
        )
        def __modify_connection_settings() -> None:
            connection_settings = UISingleSelectionInput(
                message="Select a connection setting to modify",
                choices=["Change Connection Port",
                         "Change Connection Protocol"],
                skip_message="Cancel"
            )

            connection_setting = self.ui.render(component=connection_settings)

            if not connection_setting:
                return

            try:
                if connection_setting == "Change Connection Port":
                    __modify_connection_port()

                elif connection_setting == "Change Connection Protocol":
                    __modify_connection_protocol()
            except KeyboardInterrupt:
                pass
            finally:
                __modify_connection_settings()

        try:
            __modify_connection_settings()
        except KeyboardInterrupt:
            pass

    def modify_encryption_settings(self) -> None:
        @self.ui.page(
            title=f"PassCrypt - {self.user} - Encryption Settings(Changing Symmetric Encryption Type)",
            subtitle="Press ctrl+c to cancel",
            message="Change your symmetric encryption settings.",
            style="error"
        )
        def __modify_symmetric_encryption_type() -> None:
            symmetric_encryption_input = UISingleSelectionInput(
                message="Select a symmetric encryption type",
                choices=list(get_args(SymmetricEncryptionTypes)),
                skip_message="Cancel",
                default=str(self.config.read(
                    username=self.user).SYMMETRIC_ENCRYPTION_TYPE)
            )

            symmetric_encryption: SymmetricEncryptionTypes = self.ui.render(
                component=symmetric_encryption_input)

            if not symmetric_encryption:
                return

            self.storage.change_encryption_type(
                new_symmetric_encryption_type=symmetric_encryption
            )

            self.config.update(
                key="SYMMETRIC_ENCRYPTION_TYPE",
                value=symmetric_encryption,
                username=self.user
            )

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Encryption Settings(Changing Asymmetric Encryption Type)",
            subtitle="Press ctrl+c to cancel",
            message="Change your asymmetric encryption settings."
        )
        def __modify_asymmetric_encryption_type() -> None:
            asymmetric_encryption_input = UISingleSelectionInput(
                message="Select an asymmetric encryption type",
                choices=list(get_args(AsymmetricEncryptionTypes)),
                skip_message="Cancel",
                default=str(self.config.read(
                    username=self.user).ASYMMETRIC_ENCRYPTION_TYPE)
            )

            asymmetric_encryption: AsymmetricEncryptionTypes = self.ui.render(
                component=asymmetric_encryption_input)

            if not asymmetric_encryption:
                return

            self.config.update(
                key="ASYMMETRIC_ENCRYPTION_TYPE",
                value=asymmetric_encryption,
                username=self.user
            )

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Encryption Settings(Changing Hash Type)",
            subtitle="Press ctrl+c to cancel",
            message="Change your hashing settings.",
            style="error"
        )
        def __modify_hash_type() -> None:
            hash_input = UISingleSelectionInput(
                message="Select a hash type",
                choices=list(get_args(HashTypes)),
                skip_message="Cancel",
                default=str(self.config.read(username=self.user).HASH_TYPE)
            )

            hash_type: HashTypes = self.ui.render(component=hash_input)

            if not hash_type:
                return

            self.storage.change_hash_type(
                new_hash_type=hash_type
            )

            self.config.update(
                key="HASH_TYPE",
                value=hash_type,
                username=self.user
            )

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Encryption Settings",
            subtitle="Press ctrl+c to go to main menu",
            message="Change your symmetric encryption type, asymmetric encryption type, and hash type."
        )
        def __modify_encryption_settings() -> None:
            encryption_settings = UISingleSelectionInput(
                message="Select an encryption setting to modify",
                choices=["Change Symmetric Encryption Type",
                         "Change Asymmetric Encryption Type", "Change Hash Type"],
                skip_message="Cancel"
            )

            encryption_setting = self.ui.render(component=encryption_settings)

            if not encryption_setting:
                return

            try:
                if encryption_setting == "Change Symmetric Encryption Type":
                    __modify_symmetric_encryption_type()

                elif encryption_setting == "Change Asymmetric Encryption Type":
                    __modify_asymmetric_encryption_type()

                elif encryption_setting == "Change Hash Type":
                    __modify_hash_type()
            except KeyboardInterrupt:
                pass
            finally:
                __modify_encryption_settings()

        try:
            __modify_encryption_settings()
        except KeyboardInterrupt:
            pass

    def modify_password_settings(self) -> None:
        @self.ui.page(
            title=f"PassCrypt - {self.user} - Password Settings(Changing Password Manager Type)",
            subtitle="Press ctrl+c to cancel",
            message="Change your password manager settings."
        )
        def __modify_password_manager_type() -> None:
            password_manager_input = UISingleSelectionInput(
                message="Select a password manager type",
                choices=list(get_args(PasswordManagerTypes)),
                skip_message="Cancel",
                default=str(self.config.read(
                    username=self.user).PASSWORD_MANAGER_TYPE)
            )

            password_manager: PasswordManagerTypes = self.ui.render(
                component=password_manager_input)

            if not password_manager:
                return

            self.config.update(
                key="PASSWORD_MANAGER_TYPE",
                value=password_manager,
                username=self.user
            )

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Password Settings(Changing Password Generation Rules)",
            subtitle="Press ctrl+c to cancel",
            message="Change your password generation settings."
        )
        def __modify_password_generation_rule() -> None:

            default_settings: List[str] = []
            con = self.config.read(username=self.user)

            if con.UPPER_CASE_ALLOWED:
                default_settings.append("Allow Uppercase(A-Z)")

            if con.LOWER_CASE_ALLOWED:
                default_settings.append("Allow Lowercase(a-z)")

            if con.DIGITS_ALLOWED:
                default_settings.append("Allow Digits(0-9)")

            if con.SYMBOLS_ALLOWED:
                default_settings.append("Special Characters(!@#$%^&*)")

            if con.SIMILAR_CHARACTERS_ALLOWED:
                default_settings.append(
                    "Allow Similar Characters(i, l, 1, o, 0, O)")

            password_generation_rule = UIMultiSelectionInput(
                message="Select password generation rules",
                choices=["Allow Uppercase(A-Z)", "Allow Lowercase(a-z)", "Allow Digits(0-9)",
                         "Allow Symbols(!@#$%^&*)", "Allow Similar Characters(i, l, 1, o, 0, O)"],
                default=default_settings
            )

            password_manager: List[str] = self.ui.render(
                component=password_generation_rule)

            if "Allow Uppercase(A-Z)" in password_manager:
                self.config.update(
                    key="UPPER_CASE_ALLOWED",
                    value=True,
                    username=self.user
                )
            else:
                self.config.update(
                    key="UPPER_CASE_ALLOWED",
                    value=False,
                    username=self.user
                )

            if "Allow Lowercase(a-z)" in password_manager:
                self.config.update(
                    key="LOWER_CASE_ALLOWED",
                    value=True,
                    username=self.user
                )
            else:
                self.config.update(
                    key="LOWER_CASE_ALLOWED",
                    value=False,
                    username=self.user
                )

            if "Allow Digits(0-9)" in password_manager:
                self.config.update(
                    key="DIGITS_ALLOWED",
                    value=True,
                    username=self.user
                )
            else:
                self.config.update(
                    key="DIGITS_ALLOWED",
                    value=False,
                    username=self.user
                )

            if "Allow Symbols(!@#$%^&*)" in password_manager:
                self.config.update(
                    key="SYMBOLS_ALLOWED",
                    value=True,
                    username=self.user
                )
            else:
                self.config.update(
                    key="SYMBOLS_ALLOWED",
                    value=False,
                    username=self.user
                )

            if "Allow Similar Characters(i, l, 1, o, 0, O)" in password_manager:
                self.config.update(
                    key="SIMILAR_CHARACTERS_ALLOWED",
                    value=True,
                    username=self.user
                )
            else:
                self.config.update(
                    key="SIMILAR_CHARACTERS_ALLOWED",
                    value=False,
                    username=self.user
                )

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Password Settings",
            subtitle="Press ctrl+c to go to main menu",
            message="Change your password manager type and password generation rules."
        )
        def __modify_password_settings() -> None:
            password_settings = UISingleSelectionInput(
                message="Select a password setting to modify",
                choices=["Change Password Manager Type",
                         "Change Password Generation Rules"],
                skip_message="Cancel"
            )

            password_setting = self.ui.render(component=password_settings)

            if not password_setting:
                return

            try:
                if password_setting == "Change Password Manager Type":
                    __modify_password_manager_type()

                elif password_setting == "Change Password Generation Rules":
                    __modify_password_generation_rule()

            except KeyboardInterrupt:
                pass
            finally:
                __modify_password_settings()

        try:
            __modify_password_settings()
        except KeyboardInterrupt:
            pass

    def modify_storage_settings(self) -> None:

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Reverting Commit",
            subtitle="Press ctrl+c to cancel",
            message="This will revert all the changes after any selected commit",
            style="error"
        )
        def __revert_to_commit() -> None:
            commits = self.storage.load_commits()

            choices = [f"{idx:>3}: {data[1]}" for idx, data in enumerate(commits)]

            selection_input = UISingleSelectionInput(
                message="Select commit to revert to.",
                choices=choices,
                skip_message="Cancel"
            )

            selection = self.ui.render(component=selection_input)

            if not selection:
                self.ui.render(component=UINotificationDisplay(
                    message="Reverting cancelled"
                ))

            self.ui.render(component=UIPanelDisplay(
                title="WARNING",
                message="This will revert all the changes after the selected commit. Do you want to continue?",
                subtitle="press ctrl+c to cancel",
                style="warning"
            ))

            if not self.ui.render(component=UIConfirmInput(
                message=f"Do you want to commit to {selection}",
                default=False
            )):
                self.ui.render(component=UINotificationDisplay(
                    message="Reverting cancelled"
                ))
                return
            
            self.storage.revert_to_commit(commit_hash=commits[choices.index(selection)][0])

            self.ui.render(component=UINotificationDisplay(
                message="Reverted to selected commit",
                style="success"
            ))

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Share Password",
            subtitle="Press ctrl+c to cancel",
            message="Share password to other users on network.",
            style="error"
        )
        def __share_password() -> None:
            listings = self.storage.get_listings()
            choices = [
                f"{idx:>3}: {data[0]:>20} -> {data[1]}" for idx, data in enumerate(listings)]

            selections_input = UIMultiSelectionInput(
                message="Select passwords to share",
                choices=choices,
                allow_empty=True
            )

            selected: List[str] = self.ui.render(component=selections_input)

            if not selected:
                self.ui.render(component=UINotificationDisplay(
                    message="No passwords selected, Cancelling share",
                    style="info"
                ))
                return

            sharing = []

            for selection in selected:
                sharing.append(listings[choices.index(selection)])

            data = self.storage.export_data(listings=sharing)

            share_input = UITextInput(
                message="Enter the connection code of reciever"
            )

            share_code = self.ui.render(component=share_input)

            try:
                ConnectionProtocolHandler.decode_connection_code(
                    encoded_connection_code=share_code,
                    connection_protocol=self.config.read(
                        username=self.user).CONNECTION_PROTOCOL
                )

            except ValueError:
                self.ui.render(component=UINotificationDisplay(
                    message="Invalid connection code",
                    style="error"
                ))
                return

            try:
                ConnectionProtocolHandler.send_data(
                    listings=data,
                    connection_code=share_code,
                    connection_protocol=self.config.read(
                        username=self.user).CONNECTION_PROTOCOL
                )
            except ValueError:
                self.ui.render(component=UINotificationDisplay(
                    message="Failed to share password",
                    style="error"
                ))
                return

            self.ui.render(component=UINotificationDisplay(
                message="Password shared successfully",
                style="success"
            ))

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Recieve Password (Saving Data)",
            subtitle="Press ctrl+c to cancel",
            message="Save",
            style="error"
        )
        def __save_data(data: PasswordBucket) -> None:

            self.ui.render(component=UINotificationDisplay(
                message="Password recieved successfully",
                style="success"
            ))

            listings = data.get_listings()

            table = UITableDisplay(
                title="Passwords",
                headings=["Sites/Applications", "Usernames"],
                rows=[[site, username] for site, username in listings],
                index=True
            )

            self.ui.render(component=table)

            confirm_input = UIConfirmInput(
                message="Do you want to save the password?",
                default=False
            )

            if not self.ui.render(component=confirm_input):
                self.ui.render(component=UINotificationDisplay(
                    message="Password not saved",
                    style="info"
                ))
                return

            self.storage.import_data(new_data=data)
            self.ui.render(component=UINotificationDisplay(
                message="Password saved successfully",
                style="success"
            ))

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Recieve Password",
            subtitle="Press ctrl+c to cancel",
            message="Recieve passwords from other users on network."
        )
        def __request_password() -> Any:

            asymmetric_encryption_type = self.config.read(
                username=self.user).ASYMMETRIC_ENCRYPTION_TYPE
            connection_protocol = self.config.read(
                username=self.user).CONNECTION_PROTOCOL

            connection_code, senerdetail = ConnectionProtocolHandler.request_data(
                ip=self.config.read(username=self.user).IP,
                port=self.config.read(username=self.user).DEFAULT_PORT,
                asymmetric_encryption_type=asymmetric_encryption_type,
                connection_protocol=connection_protocol
            )

            self.ui.render(component=UIPanelDisplay(
                title="Connection Code",
                subtitle="Share this code with the sender to recieve passwords",
                message=f"Connection code for sender: {connection_code}",
                style="info"
            ))

            copy(connection_code)

            self.ui.render(component=UINotificationDisplay(
                message="Connection code copied"
            ))

            try:
                data = ConnectionProtocolHandler.receive_data(
                    sender_details=senerdetail,
                    connection_protocol=connection_protocol,
                    asymmetric_encryption_type=asymmetric_encryption_type
                )
            except Exception:
                self.ui.render(component=UINotificationDisplay(
                    message="Error recieving password",
                    style="error"
                ))
                return False

            return data

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Storage Settings(Importing Storage)",
            subtitle="Press ctrl+c to cancel",
            message="Importing passwords will overwrite the existing passwords. Only import from trusted sources.",
            style="error"
        )
        def __import_storage() -> None:
            con = self.config.read(username=self.user)

            storage_input = UIFileInput(
                extension=con.IMPORT_FILE_EXTENSION,
                initial_dir=con.IMPORT_FILE_PATH
            )

            storage_file: str = self.ui.render(component=storage_input)

            if not storage_file:
                return

            secret_input = UIMasterPasswordInput(
                message="Enter decryption key for the storage file"
            )

            secret = self.ui.render(component=secret_input)

            try:
                file_data: PasswordBucket = EPT.load(
                    file_path=storage_file, secret=secret)
            except ValueError:
                self.ui.render(component=UINotificationDisplay(
                    message="Invalid decryption key",
                    style="error"
                ))
                return

            self.ui.render(component=UIPanelDisplay(
                title="WARNING",
                message="Importing passwords will overwrite the existing passwords. Do you want to continue?",
                style="warning",
                subtitle="press ctrl+c to cancel"
            ))

            if not self.ui.render(component=UIConfirmInput(message="Continue?")):
                self.ui.render(component=UINotificationDisplay(
                    message="Import cancelled",
                    style="info"
                ))
                return

            self.storage.import_data(
                new_data=file_data
            )

            self.ui.render(component=UINotificationDisplay(
                message="Storage imported successfully",
                style="success"
            ))

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Storage Settings(Exporting Storage)",
            subtitle="Press ctrl+c to cancel",
            message="Exporting passwords will create a new file with the selected passwords.",
            style="error"
        )
        def __export_storage() -> None:

            listings = self.storage.get_listings()

            if len(listings) == 0:
                self.ui.render(component=UINotificationDisplay(
                    message="No passwords found",
                    style="warning"
                ))
                return

            choices = [
                f"{idx:>3}: {data[0]:>20} -> {data[1]}" for idx, data in enumerate(listings)]

            selection_input = UIMultiSelectionInput(
                message="Select passwords to export",
                choices=choices,
                allow_empty=True
            )

            selected: List[str] = self.ui.render(component=selection_input)

            if not selected:
                self.ui.render(component=UINotificationDisplay(
                    message="No passwords selected, Cancelling export",
                    style="info"
                ))
                return

            symmetric_encryption_type_input = UISingleSelectionInput(
                message="Select a symmetric encryption type for exported file.",
                choices=list(get_args(SymmetricEncryptionTypes)),
                default=self.config.read(
                    username=self.user).SYMMETRIC_ENCRYPTION_TYPE
            )

            symmetric_encryption_type: SymmetricEncryptionTypes = self.ui.render(
                component=symmetric_encryption_type_input)

            secret_input = UIMasterPasswordInput(
                message="Enter encryption key for the storage file"
            )

            secret = self.ui.render(component=secret_input)

            export = []

            for selection in selected:
                export.append(listings[choices.index(selection)])

            self.ui.render(component=UIPanelDisplay(
                title="WARNING",
                message="Exporting passwords will create a new file with the selected passwords. Do you want to continue?",
                style="warning",
                subtitle="press ctrl+c to cancel"
            ))

            if not self.ui.render(component=UIConfirmInput(message="Continue?")):
                self.ui.render(component=UINotificationDisplay(
                    message="Export cancelled",
                    style="info"
                ))
                return

            file_path = EPT.create(
                data=self.storage.export_data(listings=export),
                secret=secret,
                symmetric_encryption_type=symmetric_encryption_type,
                file_path=self.config.read(username=self.user).EXPORT_FILE_NAME
            )

            self.ui.render(component=UINotificationDisplay(
                message=f"Storage exported successfully at {file_path}",
                style="success"
            ))

        self.ui.page(
            title=f"PassCrypt - {self.user} - Storage Settings",
            subtitle="Press ctrl+c to cancel",
            message="Change your storage settings.",
            style="error"
        )

        def __export_storage_settings() -> None:

            config_input = UIConfirmInput(
                message="Do you want to export the configuration settings?",
                default=False
            )

            if not self.ui.render(component=config_input):
                self.ui.render(component=UINotificationDisplay(
                    message="Export cancelled",
                    style="info"
                ))
                return

            file_path = self.config.export_config(username=self.user)

            self.ui.render(component=UINotificationDisplay(
                message=f"Settings exported successfully at {file_path}",
                style="success"
            ))

        self.ui.page(
            title=f"PassCrypt - {self.user} - Storage Settings",
            subtitle="Press ctrl+c to cancel",
            message="Importing settings will overwrite the existing settings and delete all your passwords. Consider backing up your data before importing settings.",
            style="error"
        )

        def __import_storage_settings() -> None:

            config_file_input = UIFileInput(
                extension=self.config.read(
                    username=self.user).CONFIG_FILE_EXTENSION,
                initial_dir=self.config.read(
                    username=self.user).IMPORT_FILE_PATH
            )

            config_file = self.ui.render(component=config_file_input)

            master_password_input = UIMasterPasswordInput(
                message="Enter your master password"
            )

            secret = self.ui.render(component=master_password_input)

            if secret != self.secret:
                self.ui.render(component=UINotificationDisplay(
                    message="Invalid master password",
                    style="error"
                ))
                return

            self.ui.render(component=UIPanelDisplay(
                title="WARNING",
                message="Importing settings will overwrite the existing settings and delete all your passwords. Do you want to continue?",
                style="warning",
                subtitle="consider exporting your passwords before importing settings",
            ))

            config_input = UIConfirmInput(
                message="Do you want to import the configuration settings?",
                default=False
            )

            if not self.ui.render(component=config_input):
                self.ui.render(component=UINotificationDisplay(
                    message="Import cancelled",
                    style="info"
                ))
                return

            self.config.import_config(
                username=self.user, file_path=config_file, secret=secret)

            self.ui.render(component=UINotificationDisplay(
                message="Settings imported successfully",
                style="success"
            ))

        def __recieve_password():
            data = __request_password()
            if data:
                __save_data(data=data)

        self.ui.page(
            title=f"PassCrypt - {self.user} - Storage Settings",
            subtitle="Press ctrl+c to go to main menu",
            message="Change your storage settings."
        )

        def __modify_storage_settings() -> None:

            choices={
                "Revert to Previous Commit": __revert_to_commit,
                "Import Storage": __import_storage, 
                "Export Storage": __export_storage, 
                "Share Password": __share_password,
                "Recieve Password": __recieve_password, 
                "Import Settings": __import_storage_settings, 
                "Export Settings": __export_storage_settings
            }

            storage_settings = UISingleSelectionInput(
                message="Select a storage setting to modify",
                choices=list(choices.keys()),
                skip_message="Cancel"
            )

            storage_setting = self.ui.render(component=storage_settings)

            if not storage_setting:
                return
            
            try:            
                choices[storage_setting]()
            except KeyboardInterrupt:
                pass
            finally:
                __modify_storage_settings()

        try:
            __modify_storage_settings()
        except KeyboardInterrupt:
            pass

    def login(self, users: List[str]) -> None:
        @self.ui.page(
            title=f"PassCrypt - Login",
            subtitle="Press ctrl+c to exit",
            message="Login to your account."
        )
        def __login(_users) -> None:
            username_input = UISingleSelectionInput(
                message="Select your username",
                choices=_users + ["Create new user"],
                default=users[0]
            )

            user: Optional[str] = self.ui.render(component=username_input)

            if not user:
                self.ui.exit(exit_message="Exiting Passcrypt CLI")
            elif user == "Create new user":
                self.setup()
            else:
                self.user = user

            secret_input = UIMasterPasswordInput(
                message=f"Enter master password for {self.user}"
            )

            secret = None

            while not secret:

                secret = self.ui.render(component=secret_input)

                if not secret:
                    raise ValueError("Invalid master password")
                else:
                    self.secret = secret
                try:
                    self.storage = self.config.get_storage(
                        username=self.user, secret=self.secret)
                except InvalidEPCFileError:
                    self.ui.render(component=UINotificationDisplay(
                        message="Invalid master password",
                        style="error"
                    ))
                    secret = None

        __login(_users=users)

    def mainloop(self) -> None:
        @self.ui.page(
            title=f"PassCrypt - {self.user} - Main Menu",
            subtitle="Press ctrl+c to exit",
            message="Welcome to Passcrypt CLI. Select an option to proceed."
        )
        def __main_menu() -> None:
            main_menu_input = UISingleSelectionInput(
                message="Select an option",
                choices=["View Passwords", "Add Password",
                         "Update Password", "Delete Password", "Settings", "Exit"]
            )

            main_menu: str = self.ui.render(component=main_menu_input)

            if main_menu == "View Passwords":
                self.view_passwords()
            elif main_menu == "Add Password":
                self.add_password()
            elif main_menu == "Update Password":
                self.update_password()
            elif main_menu == "Delete Password":
                self.delete_password()
            elif main_menu == "Settings":
                self.modify_config()
            elif main_menu == "Exit":
                self.ui.exit(exit_message="Exiting Passcrypt CLI")

        try:
            __main_menu()
        except KeyboardInterrupt:
            self.ui.exit(exit_message="Exiting Passcrypt CLI")
            
        self.mainloop()

    def view_passwords(self) -> None:

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Copy Password",
            subtitle="Press ctrl+c to cancel",
            message="Copy your stored password."
        )
        def __copy_passwords(*, _bucket: List[tuple[str, str]]) -> None:
            choices = [
                f"{idx:<2}:  {data[0]}({data[1]})" for idx, data in enumerate(_bucket, start=1)]
            selection_input = UISingleSelectionInput(
                message="Select a site/application",
                choices=choices,
                skip_message="Cancel"
            )

            selection: Optional[str] = self.ui.render(
                component=selection_input)

            if not selection:
                self.ui.render(component=UINotificationDisplay(
                    message="Copying cancelled",
                    style="info"
                ))
                return

            data = _bucket[choices.index(selection)]
            password = self.storage.get_password(
                site=data[0], username=data[1])
            copy(password)

            self.ui.render(component=UINotificationDisplay(
                message="Password copied to clipboard",
                style="success"
            ))

        @self.ui.page(
            title=f"PassCrypt - {self.user} - View Passwords",
            subtitle="Press ctrl+c to exit",
            message="View your stored passwords."
        )
        def __view_passwords() -> bool:
            bucket: List[Tuple[str, str]] = self.storage.get_listings()
            if len(bucket) == 0:
                self.ui.render(component=UINotificationDisplay(
                    message="No passwords found",
                    style="warning"
                ))
                return False

            table = UITableDisplay(
                title="Passwords",
                headings=["Sites/Applications", "Usernames"],
                rows=[[site, username] for site, username in bucket]
            )

            ask_copy = UIConfirmInput(
                message="Do you want to copy a password?",
                default=False
            )

            self.ui.render(component=table)

            if not self.ui.render(component=ask_copy):
                return False

            return True

        try:
            if __view_passwords():
                __copy_passwords(_bucket=self.storage.get_listings())
        except KeyboardInterrupt:
            pass

    def add_password(self) -> None:

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Add Password",
            subtitle="Press ctrl+c to cancel",
            message="Add a new password."
        )
        def __add_password() -> None:
            site_input = UITextSuggestionInput(
                custom_input_message="Enter a new site/application name",
                selection_message="Select a site/application name",
                choices=self.storage.get_all_sites(),
                skip_message="Add new site/application"

            )

            site: str = self.ui.render(component=site_input)

            if self.storage.is_site_exists(site=site):
                usernames: List[str] = self.storage.get_username_except_site(
                    site=site)
            else:
                usernames = []

            username_input = UITextSuggestionInput(
                custom_input_message="Enter new username",
                selection_message="Select a username",
                choices=usernames,
                skip_message="Add new username"
            )

            username = self.ui.render(component=username_input)

            password_input = UINewPasswordInput(
                password_generator_type=self.config.read(
                    username=self.user).PASSWORD_MANAGER_TYPE,
                allow_lower_case=self.config.read(
                    username=self.user).LOWER_CASE_ALLOWED,
                allow_numbers=self.config.read(
                    username=self.user).DIGITS_ALLOWED,
                allow_upper_case=self.config.read(
                    username=self.user).UPPER_CASE_ALLOWED,
                allow_similar=self.config.read(
                    username=self.user).SIMILAR_CHARACTERS_ALLOWED,
                allow_symbols=self.config.read(
                    username=self.user).SYMBOLS_ALLOWED,
                length=self.config.read(username=self.user).PASSWORD_LENGTH,
                context=[site, username],
                context_filter=self.config.read(
                    username=self.user).CONTEXT_FILTERS,
                similar_characters=self.config.read(
                    username=self.user).SIMILAR_CHARACTERS
            )

            password = self.ui.render(component=password_input)

            self.storage.add_password(
                site=site,
                username=username,
                password=password
            )

            self.ui.render(component=UINotificationDisplay(
                message="Password added successfully",
                style="success"
            ))

        try:
            __add_password()
        except KeyboardInterrupt:
            pass

    def update_password(self) -> None:

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Update Password",
            subtitle="Press ctrl+c to cancel",
            message="Update a password."
        )
        def __select_password() -> Any:

            sites = self.storage.get_all_sites()

            if len(sites) == 0:
                self.ui.render(component=UINotificationDisplay(
                    message="No passwords found",
                    style="warning"
                ))
                return False

            site_input = UISingleSelectionInput(
                message="Select a site/application to edit",
                choices=sites,
                skip_message="Cancel"
            )

            site = self.ui.render(component=site_input)

            if not site:
                self.ui.render(component=UINotificationDisplay(
                    message="Editing cancelled",
                    style="info"
                ))
                return False

            usernames = self.storage.get_usernames_by_site(site=site)

            username_input = UISingleSelectionInput(
                message="Select a username to edit",
                choices=usernames,
                skip_message="Cancel"
            )

            username = self.ui.render(component=username_input)

            if not username:
                self.ui.render(component=UINotificationDisplay(
                    message="Editing cancelled",
                    style="info"
                ))
                return False

            return site, username

        @self.ui.page(
            title=f"PassCrypt - {self.user} - Update Password",
            subtitle="Press ctrl+c to cancel",
            message="Update a password."
        )
        def __update_password(site: str, username: str) -> None:

            while True:

                change_site_input = UIConfirmInput(
                    message="Do you want to change the site/application name?",
                    default=False
                )
                change_site: bool = self.ui.render(component=change_site_input)
                if change_site:
                    sites = self.storage.get_all_sites()
                    sites.remove(site)
                    site_input = UITextSuggestionInput(
                        custom_input_message="Enter a new site/application name",
                        selection_message="Select a site/application name",
                        choices=sites,
                        skip_message="Cancel edit"
                    )

                    new_site = self.ui.render(component=site_input)
                else:
                    new_site = site

                if not new_site:
                    self.ui.render(component=UINotificationDisplay(
                        message="Editing cancelled",
                        style="info"
                    ))
                    return

                if new_site == site and change_site:
                    self.ui.render(component=UINotificationDisplay(
                        message="Site/Application name already exists",
                        style="error"
                    ))
                    continue

                change_username_input = UIConfirmInput(
                    message="Do you want to change the username?",
                    default=False
                )
                change_username: bool = self.ui.render(
                    component=change_username_input)

                if change_username:
                    usernames: List[str] = self.storage.get_usernames_by_site(
                        site=site)
                    if self.storage.is_username_exists(site=new_site, username=username):
                        usernames.remove(username)

                    username_input = UITextSuggestionInput(
                        custom_input_message="Enter a username",
                        selection_message="Select a username",
                        choices=usernames,
                        skip_message="Cancel edit"
                    )

                    new_username = self.ui.render(component=username_input)
                else:
                    new_username = username

                if not new_username:
                    self.ui.render(component=UINotificationDisplay(
                        message="Editing cancelled",
                        style="info"
                    ))
                    return

                if new_username == username and change_username:
                    self.ui.render(component=UINotificationDisplay(
                        message=f"Username already exists in {new_site}",
                        style="error"
                    ))
                    continue

                password_input = UINewPasswordInput(
                    password_generator_type=self.config.read(
                        username=self.user).PASSWORD_MANAGER_TYPE,
                    allow_lower_case=self.config.read(
                        username=self.user).LOWER_CASE_ALLOWED,
                    allow_numbers=self.config.read(
                        username=self.user).DIGITS_ALLOWED,
                    allow_upper_case=self.config.read(
                        username=self.user).UPPER_CASE_ALLOWED,
                    allow_similar=self.config.read(
                        username=self.user).SIMILAR_CHARACTERS_ALLOWED,
                    allow_symbols=self.config.read(
                        username=self.user).SYMBOLS_ALLOWED,
                    length=self.config.read(
                        username=self.user).PASSWORD_LENGTH,
                    context=[site, username],
                    context_filter=self.config.read(
                        username=self.user).CONTEXT_FILTERS,
                    similar_characters=self.config.read(
                        username=self.user).SIMILAR_CHARACTERS
                )

                password = self.ui.render(component=password_input)

                self.storage.edit_password(
                    site=site,
                    username=username,
                    password=password
                )

                break

            self.ui.render(component=UINotificationDisplay(
                message="Password updated successfully",
                style="success"
            ))

        try:
            data = __select_password()
            if data:
                __update_password(site=data[0], username=data[1])
        except KeyboardInterrupt:
            pass

    def delete_password(self) -> None:
        @self.ui.page(
            title=f"PassCrypt - {self.user} - Delete Password",
            subtitle="Press ctrl+c to cancel",
            message="Delete a password."
        )
        def __delete_password() -> None:

            sites = self.storage.get_all_sites()

            if len(sites) == 0:
                self.ui.render(component=UINotificationDisplay(
                    message="No passwords found",
                    style="warning"
                ))
                return

            site_input = UISingleSelectionInput(
                message="Select a site/application to delete",
                choices=sites,
                skip_message="Cancel"
            )

            site = self.ui.render(component=site_input)

            if not site:
                self.ui.render(component=UINotificationDisplay(
                    message="Deletion cancelled",
                    style="info"
                ))
                return

            usernames = self.storage.get_usernames_by_site(site=site)

            username_input = UISingleSelectionInput(
                message="Select a username to delete",
                choices=usernames,
                skip_message="Cancel"
            )

            username = self.ui.render(component=username_input)

            if not username:
                self.ui.render(component=UINotificationDisplay(
                    message="Deletion cancelled",
                    style="info"
                ))
                return

            self.storage.remove_password(site=site, username=username)

            self.ui.render(component=UINotificationDisplay(
                message="Password deleted successfully",
                style="success"
            ))

        try:
            __delete_password()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    try:
        PasscryptCLI().start(animate=True)
    except KeyboardInterrupt:
        os.system("cls")


