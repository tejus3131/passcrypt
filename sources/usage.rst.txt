Usage
=====

This guide will walk you through the basic usage of PassCrypt, a secure password management tool.

Getting Started
---------------

After installing PassCrypt, you can start the application by running:

.. code-block:: bash

   python main.py

On first run, you'll be prompted to set up a master password. This password will be used to encrypt and decrypt your stored passwords, so make sure it's strong and memorable.

Main Menu
---------

Once you've set up your master password (or logged in on subsequent uses), you'll see the main menu with the following options:

1. List All
2. Add Password
3. Edit Password
4. Remove Password
5. Settings

Let's go through each of these options:

List All Passwords
^^^^^^^^^^^^^^^^^^

This option displays a table of all your stored passwords, showing the site/application and username for each entry. You can also choose to copy a specific password to your clipboard from this menu.

Add Password
^^^^^^^^^^^^

To add a new password:

1. Select "Add Password" from the main menu.
2. Enter the site/application name, or select from existing ones.
3. Enter the username.
4. Either enter a password manually or let PassCrypt generate one for you.

If you choose to generate a password, you'll be asked about length and character types to include.

Edit Password
^^^^^^^^^^^^^

To edit an existing password:

1. Select "Edit Password" from the main menu.
2. Choose the site/application and username of the password you want to edit.
3. You'll have the option to change the site/application name, username, and/or password.

Remove Password
^^^^^^^^^^^^^^^

To remove a password:

1. Select "Remove Password" from the main menu.
2. Choose the site/application and username of the password you want to remove.
3. Confirm the deletion.

Settings
^^^^^^^^

The Settings menu provides several options:

- Reset Master Password: Change your master password.
- Import a PassCrypt storage: Import passwords from another PassCrypt export.
- Export your PassCrypt storage: Export your passwords to a file.
- Export your PassCrypt logs: Export the application logs.
- Clear all passwords: Delete all stored passwords.
- Clear logs: Clear the application logs.
- Remove PassCrypt storage: Delete the PassCrypt storage file.

Best Practices
--------------

1. **Master Password**: Choose a strong, unique master password and never share it with anyone.
2. **Regular Backups**: Use the export feature regularly to back up your passwords.
3. **Password Generation**: When possible, use PassCrypt's password generator to create strong, unique passwords for each site.
4. **Regular Updates**: Keep PassCrypt updated to ensure you have the latest security features.

Security Notes
--------------

- PassCrypt uses strong encryption to protect your passwords, but the security of your data ultimately depends on keeping your master password safe.
- Always be cautious when exporting your password data or logs, and ensure you store any exported files securely.
- If you suspect your master password has been compromised, change it immediately using the "Reset Master Password" option in the Settings menu.

Troubleshooting
---------------

If you encounter any issues while using PassCrypt:

1. Check the application logs (you can export them from the Settings menu).
2. Ensure you're using the latest version of PassCrypt.
3. If the problem persists, please report the issue on our GitHub page, providing as much detail as possible about the problem and your system configuration.