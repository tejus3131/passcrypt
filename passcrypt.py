
# SIMILAR_CHARS: Dict[str, str] = {
#     "o": "0", "0": "o",
#     "s": "5", "5": "s",
#     "b": "8", "8": "b",
#     "z": "2", "2": "z",
#     "q": "9", "9": "q",
#     "1": "l", "l": "1",
#     "3": "e", "e": "3",
#     "a": "4", "4": "a",
#     "t": "7", "7": "t"
# }

# CONTEXT_FILTER: List[str] = [
#     "gmail", "email", "com", "in", "co", "uk", "outlook",
#     "onedrive", "yahoo", "google", "test", "password",
#     "admin", "user", "login", "secure", "key", "root",
#     "123456", "qwerty", "abc123", "password123", "letmein",
#     "welcome", "admin123", "123456789", "12345678", "12345",
#     "1234567", "1234567890", "password1", "1234", "password1234",
#     "password12", "password12345", "password123456", "password1234567",
#     "password12345678", "password123456789", "password1234567890",
#     "default", "admin1", "admin2", "user1", "user2",
#     "welcome1", "test123", "guest", "guest1", "guest123",
#     "changeme", "changeme123", "root123", "rootpass", "system",
#     "sysadmin", "superuser", "administrator", "manager", "testuser",
#     "public", "demo", "example", "temp", "temp123",
#     "tempuser", "publicuser", "public123", "trial", "trial123"
# ]

# class PasswordManager:
#     """
#     A class to manage the Password Manager application.
#     """

#     def __init__(self) -> None:
#         """
#         Initialize the PasswordManager object.

#         :return: None
#         """
#         self.ui = UserInterface()

#     def __call__(self) -> None:
#         """
#         Run the Password Manager application.

#         :return: None
#         """
#         logging.info("Starting PassCrypt Application")
#         if not os.path.exists(PATHS["STORAGE_FILE"]):
#             logging.info("Initializing PassCrypt")
#             status, self.storage = self.init_pm()
#         else:
#             logging.info("Logging into PassCrypt")
#             status, self.storage = self.login()

#         if status:
#             logging.info("Access granted!")
#             self.main_menu()
#         else:
#             logging.error("Access denied!")
#             self.ui.show_error(
#                 "An error occurred while initializing the Password Manager")

#     def init_pm(self) -> Tuple[bool, Optional[Storage]]:
#         """
#         Initialize the Password Manager

#         :return: A tuple containing the status and the storage object.
#         """
#         self.ui.new_page(
#             f"Initialization",
#             "Press ctrl+c to exit.",
#             "Introducing PassCrypt, the ultimate solution for secure and effortless password management. " +
#             "With advanced encryption technology, PassCrypt ensures that your passwords are stored " +
#             "safely, protecting them from unauthorized access. Our user-friendly interface makes it easy " +
#             "to encrypt, store, and retrieve your passwords, offering you peace of mind and convenience. " +
#             "Whether you're managing passwords for personal use or for a team, PassCrypt provides robust " +
#             "security features to keep your sensitive information safe. Trust PassCrypt for reliable " +
#             "password encryption and storage, so you can focus on what matters most without worrying " +
#             "about password security. Try PassCrypt today!"
#         )
#         os.makedirs(os.path.dirname(PATHS["STORAGE_FILE"]), exist_ok=True)
#         master_password = self.generate_master()
#         try:
#             storage = Storage(master_password, True)
#         except Exception as e:
#             self.ui.show_error(
#                 "An error occurred while initializing the Password Manager." + str(e))
#             return False, None
#         return True, storage

#     def generate_master(self):
#         """
#         Generate the master password for the Password Manager.

#         :return: The generated master password.
#         """
#         final_password = None
#         while not final_password:
#             master_password = self.ui.ui_input(
#                 "MASTER_PASSWORD",
#                 input_message="Set the Master Password:"
#             )
#             master_password_confirm = self.ui.ui_input(
#                 "MASTER_PASSWORD",
#                 input_message="Confirm the Master Password:"
#             )
#             if master_password == master_password_confirm:
#                 final_password = master_password
#             else:
#                 self.ui.show_error("Passwords do not match. Try again.")
#         return final_password

#     def login(self) -> Tuple[bool, Optional[Storage]]:
#         """
#         Login to access the password manager

#         :return: A tuple containing the status and the storage object.
#         """
#         self.ui.new_page(f"Login", "Press ctrl+c to exit.")
#         master_password = self.ui.ui_input(
#             "MASTER_PASSWORD",
#             input_message="Enter the Master Password:"
#         )

#         try:
#             storage = Storage(master_password, False)
#             self.ui.show_success("Access granted! Welcome to PassCrypt.")
#             return True, storage
#         except InvalidToken:
#             self.ui.show_error("Invalid Master Password! Access denied.")
#             return False, None

#     def main_menu(self) -> None:
#         """
#         Display the main menu of the Password Manager.

#         :return: None
#         """
#         self.ui.new_page("Main Menu", "Press ctrl+c to exit.")
#         choices = {
#             "List All": self.list_all,
#             "Add Password": self.add_password,
#             "Edit Password": self.edit_password,
#             "Remove Password": self.remove_password,
#             "Settings": self.authenticate
#         }

#         option = self.ui.ui_input(
#             "SELECTION",
#             selection_message="Choose an option:",
#             choices=list(choices.keys()),
#             default="List All"
#         )
#         try:
#             choices[option]()
#         except KeyboardInterrupt:
#             self.ui.show_info("Returning to the Main Menu.")
#         self.main_menu()

#     def authenticate(self) -> None:
#         """
#         Authenticate the user to access the settings.

#         :return: None
#         """
#         self.ui.new_page("Authentication",
#                          "Press ctrl+c to return to the Main Menu.")

#         master_password = self.ui.ui_input(
#             "MASTER_PASSWORD",
#             input_message="Enter the Master Password:"
#         )
#         if self.storage and not self.storage.validate_secret(master_password):
#             self.ui.show_error(
#                 "Invalid Master Password! Access denied.")
#         else:
#             self.settings()

#     def add_password(self) -> None:
#         """
#         Add a password to the storage.

#         :return: None
#         """
#         self.ui.new_page("Add Password", "Press ctrl+c to abort.")

#         if not self.storage:
#             self.ui.show_error(
#                 "An error occurred while accessing the storage.")
#             return

#         sites = self.storage.get_all_sites()
#         usernames = self.storage.get_all_usernames()

#         site = self.ui.ui_input(
#             "BOTH",
#             selection_message="Select a site/application (Press ENTER to add new site/application):",
#             choices=sites,
#             input_message="Enter new site/application:",
#             skip_message="Add new site/application"
#         )

#         usernames = [
#             username
#             for username
#             in usernames
#             if username not in self.storage.get_username_for_site(site)
#         ]

#         username = None
#         while not username:
#             username = self.ui.ui_input(
#                 "BOTH",
#                 selection_message="Select a username (Press ENTER to add new username):",
#                 choices=usernames,
#                 input_message="Enter new username:",
#                 skip_message="Add new username"
#             )
#             if self.storage.username_exist(site, username):
#                 self.ui.show_error(
#                     f"Password for {site} - {username} already exists!")
#                 username = None

#         self.storage.add_password(
#             site, username, self.ui.ui_input(
#                 "PASSWORD",
#                 site=site,
#                 username=username
#             )
#         )
#         self.ui.show_success(
#             f"Password for {site} - {username} added successfully!")
#         pyperclip.copy(self.storage.get_password_for_site(site, username))
#         logging.info(f"Password for {site} - {username} added successfully!")

#     def remove_password(self) -> None:
#         """
#         Remove a password from the storage.

#         :return: None
#         """
#         self.ui.new_page("Remove Password", "Press ctrl+c to abort.")

#         if not self.storage:
#             self.ui.show_error(
#                 "An error occurred while accessing the storage.")
#             return

#         sites = self.storage.get_all_sites()
#         if len(sites) == 0:
#             self.ui.show_error("No passwords found to remove!")
#             return

#         site = None
#         while not site:
#             site = self.ui.ui_input(
#                 "SELECTION",
#                 selection_message="Select a site/application to remove the password:",
#                 choices=sites
#             )

#         username = None
#         while not username:
#             username = self.ui.ui_input(
#                 "SELECTION",
#                 selection_message="Select a username to remove the password:",
#                 choices=self.storage.get_username_for_site(site)
#             )
#         if self.ui.ui_input(
#                 "CONFIRM",
#                 input_message=f"Are you sure you want to remove the password for {username} - {site}?",
#                 default=False
#         ) == 'y':
#             self.storage.remove_password(site, username)
#             self.ui.show_success(
#                 f"Password for {site} - {username} removed successfully!")
#             logging.info(
#                 f"Password for {site} - {username} removed successfully!")
#         else:
#             self.ui.show_info(
#                 f"Returning to the Main Menu.")

#     def edit_password(self) -> None:
#         """
#         Edit a password in the storage.

#         :return: None
#         """
#         self.ui.new_page("Edit Password", "Press ctrl+c to abort.")

#         if not self.storage:
#             self.ui.show_error(
#                 "An error occurred while accessing the storage.")
#             return

#         sites = self.storage.get_all_sites()
#         if len(sites) == 0:
#             self.ui.show_error("No passwords found to edit!")
#             return

#         previous_site = self.ui.ui_input(
#             "SELECTION",
#             selection_message="Select a site/application to edit the password:",
#             choices=sites
#         )

#         previous_user = self.ui.ui_input(
#             "SELECTION",
#             selection_message="Select a username to edit the password:",
#             choices=self.storage.get_username_for_site(previous_site)
#         )

#         sites.remove(previous_site)

#         if self.ui.ui_input(
#                 "CONFIRM",
#                 input_message="Change the site/application name?",
#                 default=False
#         ) == 'y':
#             self.ui.clear_last_line()
#             new_site = None
#             while not new_site:
#                 new_site = self.ui.ui_input(
#                     "BOTH",
#                     selection_message="Select the site/application (Press ENTER to keep the current site/application):",
#                     choices=sites,
#                     input_message="Enter the new site/application name:",
#                     skip_message="Add new site/application"
#                 )
#                 if previous_user in self.storage.get_username_for_site(new_site):
#                     self.ui.show_error(
#                         f"Password for {new_site} - {previous_user} already exists!")
#                     self.ui.clear_last_line()
#                     new_site = None
#         else:
#             new_site = previous_site

#         if self.storage.site_exist(new_site):
#             usernames = self.storage.get_username_for_site(new_site)
#             usernames.remove(previous_user)
#         else:
#             usernames = []

#         if self.ui.ui_input(
#                 "CONFIRM",
#                 input_message="Change the username?",
#                 default=False
#         ) == 'y':
#             self.ui.clear_last_line()
#             new_user = self.ui.ui_input(
#                 "BOTH",
#                 selection_message="Select the username (Press ENTER to keep the current username):",
#                 choices=usernames,
#                 input_message="Enter the new username:",
#                 skip_message="Add new username"
#             )
#         else:
#             new_user = previous_user

#         if self.ui.ui_input(
#                 "CONFIRM",
#                 input_message="Change the password?",
#                 default=False
#         ) == 'y':
#             self.ui.clear_last_line()
#             new_password = self.ui.ui_input(
#                 "PASSWORD",
#                 site=new_site,
#                 username=new_user
#             )
#         else:
#             new_password = self.storage.get_password_for_site(
#                 previous_site, previous_user) or ""

#         self.storage.edit_password(
#             previous_site, previous_user, new_site, new_user, new_password)
#         self.ui.show_success(
#             f"Password for {previous_site} - {previous_user} edited successfully!")
#         logging.info(
#             f"Password for {previous_site} - {previous_user} edited successfully!")

#     def list_all(self) -> None:
#         """
#         List all passwords in the storage.

#         :return: None
#         """
#         if not self.storage:
#             self.ui.show_error(
#                 "An error occurred while accessing the storage.")
#             logging.error("An error occurred while accessing the storage.")
#             return

#         self.ui.new_page("List All Passwords",
#                          "Press ctrl+c to return to the Main Menu.")

#         if not self.storage.get_all_sites():
#             self.ui.show_info("No passwords found!")
#             return

#         self.ui.create_table(
#             "Stored Passwords",
#             ["ID", "Site/Application", "Username"],
#             [[str(idx), site, username] for idx, (site, username)
#              in enumerate(self.storage.list_all(), start=1)]
#         )

#         if self.ui.ui_input(
#                 "CONFIRM",
#                 input_message="Copy a password?",
#                 default=False
#         ) == 'y':
#             self.ui.new_page(
#                 "Copy Password", "Press ctrl+c to return to the Main Menu.")
#             choices = [
#                 f"{idx:>3}:  {site:>20} ->  {username:>20}"
#                 for idx, (site, username)
#                 in enumerate(self.storage.list_all(), start=1)
#             ]
#             selected = self.ui.ui_input(
#                 "SELECTION",
#                 selection_message="Select a password to copy:",
#                 choices=choices
#             )

#             site, username = self.storage.list_all()[
#                 int(choices.index(selected))]
#             pyperclip.copy(self.storage.get_password_for_site(site, username))
#             self.ui.show_success(
#                 f"Password for {site} - {username} copied to clipboard!\nReturning to the Main Menu.")
#             logging.info(
#                 f"Password for {site} - {username} copied to clipboard!")
#         else:
#             self.ui.show_info(
#                 "Returning to the Main Menu.")

#     def settings(self) -> None:
#         """
#         Display the settings menu.

#         :return: None
#         """
#         self.ui.new_page(
#             "Settings", "Press ctrl+c to return to the Main Menu.")

#         choices = {
#             "Return to Main Menu\n": lambda: self.ui.show_info("Returning to the Main Menu."),
#             "Reset Master Password\n": self.change_master_password,
#             "Import a PassCrypt storage\n": self.import_pc,
#             "Export your PassCrypt storage": self.export_pc,
#             "Export your PassCrypt logs\n": self.export_logs,
#             "Clear all passwords": self.clear_all_data,
#             "Clear logs\n": self.clear_logs,
#             "Remove PassCrypt storage": self.remove_pc
#         }

#         option = self.ui.ui_input(
#             "SELECTION",
#             selection_message="Choose an option:",
#             choices=list(choices.keys()),
#             default="Return to Main Menu\n"
#         )

#         try:
#             choices[option]()
#         except KeyboardInterrupt:
#             self.ui.show_info("Returning to the Main Menu.")

#     def clear_logs(self) -> None:
#         """
#         Clear the logs.

#         :return: None
#         """

#         if not self.storage:
#             self.ui.show_error(
#                 "An error occurred while accessing the storage.")
#             logging.error("An error occurred while accessing the storage.")
#             return

#         self.ui.new_page("Clear Logs", "Press ctrl+c to abort.")
#         if self.ui.ui_input(
#                 "CONFIRM",
#                 input_message="Are you sure you want to clear the logs?",
#                 default=False
#         ) == 'y':
#             self.storage.clear_logs()
#             self.ui.show_success("Logs cleared successfully!")
#             logging.info("Logs cleared successfully!")
#         else:
#             self.ui.show_info("Returning to the Main Menu.")

#     def remove_pc(self) -> None:
#         """
#         Remove the PassCrypt storage file.  

#         :return: None
#         """
#         self.ui.new_page("Remove PassCrypt Storage",
#                          "Press ctrl+c to abort.")
#         self.ui.show_error_panel(
#             "WARNING",
#             "Remove PassCrypt Storage",
#             "This action will remove the PassCrypt storage file and all its contents. This action is irreversible."
#         )
#         if self.ui.ui_input(
#                 "CONFIRM",
#                 input_message="Are you sure you want to remove the PassCrypt storage?",
#                 default=False
#         ) == 'y':
#             os.remove(PATHS["STORAGE_FILE"])
#             self.ui.show_success("PassCrypt storage removed successfully!")
#             logging.info("PassCrypt storage removed successfully!")
#             os.system('cls' if os.name == 'nt' else 'clear')
#             sys.exit(0)
#         else:
#             self.ui.show_info("Returning to the Main Menu.")

#     def export_logs(self) -> None:
#         """
#         Export the PassCrypt logs to a file.

#         :return: None
#         """
#         if not self.storage:
#             self.ui.show_error(
#                 "An error occurred while accessing the storage.")
#             logging.error("An error occurred while accessing the storage.")
#             return
#         self.ui.new_page("Export PassCrypt Logs", "Press ctrl+c to abort.")
#         self.ui.show_info_panel(
#             "INFO",
#             "Export PassCrypt Logs",
#             "This action will export the PassCrypt logs to a file."
#         )
#         if self.ui.ui_input(
#                 "CONFIRM",
#                 input_message="Are you sure you want to export the PassCrypt logs?",
#                 default=False
#         ) == 'n':
#             self.ui.show_info("Returning to the Main Menu.")
#             return

#         path = self.storage.export_logs()
#         self.ui.show_success(
#             f"PassCrypt logs exported successfully!\nFile saved at: {path}\nReturning to the Main Menu.")
#         logging.info("PassCrypt logs exported successfully!")

#         self.ui.wait()

#     def export_pc(self) -> None:
#         """
#         Export the PassCrypt storage to a file.

#         :return: None
#         """
#         if not self.storage:
#             self.ui.show_error(
#                 "An error occurred while accessing the storage.")
#             logging.error("An error occurred while accessing the storage.")
#             return

#         self.ui.new_page("Export PassCrypt Storage",
#                          "Press ctrl+c to abort.")
#         self.ui.show_info_panel(
#             "INFO",
#             "Confirm Export",
#             "This action will export the PassCrypt storage to a file."
#         )
#         if not self.ui.ui_input(
#                 "CONFIRM",
#                 input_message="Are you sure you want to export the PassCrypt storage?",
#                 default=False
#         ) == 'y':
#             self.ui.show_info("Returning to the Main Menu.")
#             return

#         secret = self.ui.ui_input(
#             "MASTER_PASSWORD",
#             input_message="Enter key for encryption:"
#         )

#         path = self.storage.export_storage(secret)
#         self.ui.show_success(
#             f"PassCrypt storage exported successfully!\nFile saved at: {path}\nReturning to the Main Menu.")
#         logging.info("PassCrypt storage exported successfully to: " + path)

#         self.ui.wait()

#     def import_pc(self) -> None:
#         """
#         Import a PassCrypt storage from a file.

#         :return: None
#         """
#         if not self.storage:
#             self.ui.show_error(
#                 "An error occurred while accessing the storage.")
#             logging.error("An error occurred while accessing the storage.")
#             return
#         self.ui.new_page("Import PassCrypt Storage",
#                          "Press ctrl+c to abort.")
#         self.ui.show_error_panel(
#             "WARNING",
#             "Import PassCrypt Storage",
#             """This action will import a PassCrypt storage file.
#             It may have gibberish data.
#             Make sure you trust the source of the file."""
#         )
#         path = self.ui.ui_input("FILE")

#         final_password = self.ui.ui_input(
#             "MASTER_PASSWORD",
#             input_message="Enter key for decryption:"
#         )

#         self.storage.import_storage(final_password, path, self.ui.ui_input)
#         self.ui.show_success(
#             "PassCrypt storage imported successfully!\nReturning to the Main Menu.")
#         logging.info("PassCrypt storage imported successfully!")
#         self.ui.wait()

#     def clear_all_data(self) -> None:
#         """
#         Clear all passwords from the storage.

#         :return: None
#         """
#         if not self.storage:
#             self.ui.show_error(
#                 "An error occurred while accessing the storage.")
#             logging.error("An error occurred while accessing the storage.")
#             return

#         self.ui.new_page("Clear All Data", "Press ctrl+c to abort.")
#         self.ui.show_error_panel(
#             "WARNING",
#             "Clear All Data",
#             "This action will clear all passwords from the storage. This action is irreversible."
#         )
#         if not self.ui.ui_input(
#                 "CONFIRM",
#                 input_message="Are you sure you want to clear all passwords?",
#                 default=False
#         ) == 'y':
#             self.ui.show_info("Returning to the Main Menu.")
#             return
#         self.storage.clear_all_data()
#         self.ui.show_success("All passwords cleared successfully!")
#         logging.info("All passwords cleared successfully!")

#     def change_master_password(self) -> None:
#         """
#         Change the master password for the storage.

#         :return: None
#         """
#         if not self.storage:
#             self.ui.show_error(
#                 "An error occurred while accessing the storage.")
#             logging.error("An error occurred while accessing the storage.")
#             return
#         self.ui.new_page("Reset Master Password",
#                          "Press ctrl+c to abort.")
#         self.ui.show_error_panel(
#             "WARNING",
#             "Reset Master Password",
#             "This action will reset the Master Password for the storage."
#         )

#         new_password = self.generate_master()
#         self.storage.change_master_password(new_password)
#         self.ui.show_success("Master Password reset successfully!")
#         logging.info("Master Password reset successfully!")
