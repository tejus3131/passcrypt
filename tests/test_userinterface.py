"""
pypasscrypt.userinterface
-------------------------

A module to handle the user interface for the Password Manager.

Interfaces:
----------
- `IUIComponent`: A class to handle the user interface components.
- `IUIDisplayComponent`: A class to handle displaying messages to the user.
- `IUIInputComponent`: A class to handle user input for the Password Manager.

Types:
-----
- `DisplayStyle`: The display style for the user interface.

Classes:
-------
- `UI`: A class to handle the user interface helper functions.
- `UIPanelDisplay`: A class to handle the user interface panels.
- `UIMessageDisplay`: A class to handle the user interface messages.
- `UINotificationDisplay`: A class to handle the user interface notifications.
- `UITableDisplay`: A class to handle the user interface tables.
- `UITextInput`: A class to handle user input for the Password Manager.
- `UISingleSelectionInput`: A class to handle selection input for the Password Manager.
- `UIMultiSelectionInput`: A class to handle multiple selection input for the Password Manager.
- `UIConfirmInput`: A class to handle confirmation input for the Password Manager.
- `UITextSuggestionInput`: A class to handle suggestion input for the Password Manager.
- `UIPasswordInput`: A class to handle password input for the Password Manager.
- `UINewPasswordInput`: A class to handle password input for the Password Manager.
- `UIMasterPasswordInput`: A class to handle master password input for the Password Manager.
- `UINewMasterPasswordInput`: A class to handle new master password input for the Password Manager.
- `UIFileInput`: A class to handle file input for the Password Manager.

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
    'IUIComponent',
    'IUIDisplayComponent',
    'IUIInputComponent',
    'DisplayStyle',
    'UI',
    'UIPanelDisplay',
    'UIMessageDisplay',
    'UINotificationDisplay',
    'UITableDisplay',
    'UITextInput',
    'UISingleSelectionInput',
    'UIMultiSelectionInput',
    'UIConfirmInput',
    'UITextSuggestionInput',
    'UIPasswordInput',
    'UINewPasswordInput',
    'UIMasterPasswordInput',
    'UINewMasterPasswordInput',
    'UIFileInput',
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    '__status__'
]

import os
import sys
from time import sleep
from tkinter import filedialog
from string import punctuation
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from InquirerPy.prompts.list import ListPrompt
from InquirerPy.prompts.input import InputPrompt
from InquirerPy.prompts.confirm import ConfirmPrompt
from InquirerPy.prompts.filepath import FilePathPrompt
from InquirerPy.prompts.checkbox import CheckboxPrompt
from typing import (
    List,
    Any,
    Literal,
    Optional,
    Callable
)
from abc import (
    ABC,
    abstractmethod
)

DisplayStyle = Literal["error", "success", "info", "warning", "text"]
"""
pypasscrypt.userinterface.DisplayStyle
--------------------------------------

The display style for the user interface.

Values:
- `error`: The error style.
- `success`: The success style.
- `info`: The informational style.
- `warning`: The warning style.
- `text`: The text style.

Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
"""


class UI:
    """
    pypasscrypt.userinterface.UI
    ----------------------------------

    A class to handle the user interface helper functions.

    Methods:
    -------
    - `clear_all()`: Clear the terminal screen.
    - `clear_lines()`: Clear the lines in the terminal.
    - `sleep()`: Sleep for a few seconds.
    - `wait()`: Wait for the user to press ENTER.
    - `exit()`: Exit the Password Manager.

    Decorators:
    ----------
    - `page()`: Display a page in the user interface.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self) -> None:
        """
        pypasscrypt.userinterface.UI.__init__
        ------------------------------------------

        Initialize the UI object.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.console: Console = Console()

    def clear_all(self) -> None:
        """
        pypasscrypt.userinterface.UI.clear_all
        ------------------------------------------------

        Clear the terminal screen.

        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.console.clear()

    def clear_lines(self, *, lines: int = 1) -> None:
        """
        pypasscrypt.userinterface.UI.clear_lines
        ----------------------------------------------

        Clear the lines in the terminal.

        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.console.print("[bold cyan]Clearing the lines...[/bold cyan]")
        for _ in range(lines + 1):
            sys.stdout.write('\033[F')  # Move the cursor up one line
            sys.stdout.write('\033[K')  # Clear the line
            sys.stdout.flush()

    def sleep(self, *, delay: int) -> None:
        """
        pypasscrypt.userinterface.UI.sleep
        ---------------------------------------

        Sleep for a few seconds.

        :param delay: The delay in seconds.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.console.print("")
        sleep(delay)

    def wait(self, *, wait_message: str) -> None:
        """
        pypasscrypt.userinterface.UI.wait
        ---------------------------------------

        Wait for the user to press ENTER.

        :param wait_message: The message to display to the user.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.console.print(f"\n[bold cyan]{wait_message}[/bold cyan]")
        input()

    def exit(self, *, exit_message: str) -> None:
        """
        pypasscrypt.userinterface.UI.exit
        ---------------------------------------

        Exit the Password Manager.

        :param exit_message: The exit message to display to the user.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.console.print(exit_message, style="bold cyan")
        sleep(2)
        self.clear_all()
        sys.exit(0)

    def page(self, *, title: str, subtitle: str) -> Callable[..., Any]:
        """
        pypasscrypt.userinterface.UI.page
        ---------------------------------------

        Display a page in the user interface.

        :param title: The title of the page.
        :param subtitle: The subtitle of the page.
        :return: The wrapped function.

        Example:
        -------
        ```python
        ui: UI = UI()

        @ui.page(title="Page Title", subtitle="Page Subtitle")
        def display_page() -> None:
            ui.console.print("This is a page.")

        display_page()
        ```

        `OR`

        ```python
        class PageHandler:
            def __init__(self):
                self.ui = UI()

            def setup_page(self):
                @self.ui.page(title="Page Title", subtitle="Page Subtitle")
                def display_page() -> None:
                    self.ui.console.print("This is a page.")
                
                display_page()

        handler = PageHandler()
        handler.setup_page()
        ```

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            """
            pypasscrypt.userinterface.UI.page.<decorator>
            ---------------------------------------------------

            Decorator to wrap the function.
            
            :param func: The function to wrap.
            :return: The wrapped function.
            
            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """

            def wrapper(*args, **kwargs) -> Any:
                """
                pypasscrypt.userinterface.UI.page.<decorator>.<wrapper>
                ----------------------------------------------------------------

                Wrapper function to display the page.

                :param args: The arguments to pass to the function.
                :param kwargs: The keyword arguments to pass to the function.

                Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
                """
                self.console.print("\n\n")
                navbar = UIPanelDisplay(
                    title=title,
                    subtitle=subtitle,
                    message="",
                    style="text"
                )
                navbar(ui=self)
                self.console.print("\n")
                return func(*args, **kwargs)

            return wrapper

        return decorator


class IUIComponent(ABC):
    """
    pypasscrypt.userinterface.IUIComponent
    --------------------------------------

    A class to handle the user interface components.

    Supported Interfaces:
    ---------------------
    - `IUIDisplayComponent`
    - `IUIInputComponent`

    Supported Classes:
    ------------------
    - `UIPanelDisplay`
    - `UIMessageDisplay`
    - `UINotificationDisplay`
    - `UITableDisplay`
    - `UITextInput`
    - `UISingleSelectionInput`
    - `UIMultiSelectionInput`
    - `UIConfirmInput`
    - `UITextSuggestionInput`
    - `UIPasswordInput`
    - `UINewPasswordInput`
    - `UIMasterPasswordInput`
    - `UINewMasterPasswordInput`
    - `UIFileInput`

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @abstractmethod
    def __call__(self, *, ui: UI) -> Optional[Any]:
        """
        pypasscrypt.userinterface.IUIComponent.__call__
        ----------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: The user input or None.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class IUIDisplayComponent(IUIComponent, ABC):
    """
    pypasscrypt.userinterface.IUIDisplayComponent
    ---------------------------------------------
    
    A class to handle displaying messages to the user.

    Supported Classes:
    ------------------
    - `UIPanelDisplay`
    - `UIMessageDisplay`
    - `UINotificationDisplay`

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @abstractmethod
    def __show_error(self) -> Any:
        """
        pypasscrypt.userinterface.IUIDisplayComponent.__show_error
        ---------------------------------------------------------

        Display an error message to the user.

        :return: Any

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @abstractmethod
    def __show_success(self) -> Any:
        """
        pypasscrypt.userinterface.IUIDisplayComponent.__show_success
        ------------------------------------------------------------

        Display a success message to the user.

        :return: Any

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @abstractmethod
    def __show_info(self) -> Any:
        """
        pypasscrypt.userinterface.IUIDisplayComponent.__show_info
        ---------------------------------------------------------

        Display an informational message to the user.

        :return: Any

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @abstractmethod
    def __show_warning(self) -> Any:
        """
        pypasscrypt.userinterface.IUIDisplayComponent.__show_warning
        ------------------------------------------------------------

        Display a warning message to the user.

        :return: Any

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @abstractmethod
    def __show_text(self) -> Any:
        """
        pypasscrypt.userinterface.IUIDisplayComponent.__show_text
        --------------------------------------------------------

        Display a text message to the user.

        :return: Any

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @abstractmethod
    def __call__(self, *, ui: UI) -> None:
        """
        pypasscrypt.userinterface.IUIDisplayComponent.__call__
        -------------------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class IUIInputComponent(IUIComponent, ABC):
    """
    pypasscrypt.userinterface.IUIInputComponent
    ------------------------------------------

    A class to handle user input for the Password Manager.

    Supported Classes:
    ------------------
    - `UITextInput`
    - `UISingleSelectionInput`
    - `UIMultiSelectionInput`
    - `UIConfirmInput`
    - `UITextSuggestionInput`
    - `UIPasswordInput`
    - `UINewPasswordInput`
    - `UIMasterPasswordInput`
    - `UINewMasterPasswordInput`
    - `UIFileInput`

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @abstractmethod
    def __call__(self, *, ui: UI) -> Any:
        """
        pypasscrypt.userinterface.IUIInputComponent.__call__
        ----------------------------------------------------

        Display the user interface.

        :return: Any

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class UIPanelDisplay(IUIDisplayComponent):
    """
    pypasscrypt.userinterface.UIPanelDisplay
    ----------------------------------------

    A class to handle the user interface panels.

    Example:
    -------
    ```python
    panel: UIPanelDisplay = UIPanelDisplay(
        title="Panel Title",
        subtitle="Panel Subtitle",
        message="Panel Message",
        style="info"
    )
    panel(ui=ui)
    ```

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            title: str,
            subtitle: str,
            message: str,
            style: DisplayStyle = "text"
    ) -> None:
        """
        pypasscrypt.userinterface.UIPanelDisplay.__init__
        ------------------------------------------------

        Initialize the UIPanel object.
        
        :param title: The title of the panel.
        :param subtitle: The subtitle of the panel.
        :param message: The message of the panel.
        :param style: The style of the panel.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.title: str = title  # sets the title of the panel
        self.subtitle: str = subtitle  # sets the subtitle of the panel
        self.message: str = message  # sets the message of the panel
        self.style: DisplayStyle = style  # sets the style of the panel

    def __show_error(self) -> Panel:
        """
        pypasscrypt.userinterface.UIPanelDisplay.__show_error
        ----------------------------------------------------

        Display an error message to the user.

        :return: Panel

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return Panel(
            self.message,
            title=self.title,
            title_align="center",
            subtitle=self.subtitle,
            subtitle_align="center",
            border_style="red",
            style="red",
            padding=(1, 2)
        )  # returns the error panel

    def __show_success(self) -> Panel:
        """
        pypasscrypt.userinterface.UIPanelDisplay.__show_success
        ------------------------------------------------------

        Display a success message to the user.

        :return: Panel

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return Panel(
            self.message,
            title=self.title,
            title_align="center",
            subtitle=self.subtitle,
            subtitle_align="center",
            border_style="green",
            style="green",
            padding=(1, 2)
        )  # returns the success panel

    def __show_info(self) -> Panel:
        """
        pypasscrypt.userinterface.UIPanelDisplay.__show_info
        ---------------------------------------------------

        Display an informational message to the user.

        :return: Panel

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return Panel(
            self.message,
            title=self.title,
            title_align="center",
            subtitle=self.subtitle,
            subtitle_align="center",
            border_style="blue",
            style="blue",
            padding=(1, 2)
        )  # returns the informational panel

    def __show_warning(self) -> Panel:
        """
        pypasscrypt.userinterface.UIPanelDisplay.__show_warning
        ------------------------------------------------------

        Display a warning message to the user.

        :return: Panel

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return Panel(
            self.message,
            title=self.title,
            title_align="center",
            subtitle=self.subtitle,
            subtitle_align="center",
            border_style="yellow",
            style="yellow",
            padding=(1, 2)
        )  # returns the warning panel

    def __show_text(self) -> Panel:
        """
        pypasscrypt.userinterface.UIPanelDisplay.__show_text
        ---------------------------------------------------

        Display a text message to the user.

        :return: Panel

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return Panel(
            self.message,
            title=self.title,
            title_align="center",
            subtitle=self.subtitle,
            subtitle_align="center",
            border_style="cyan",
            style="cyan",
            padding=(1, 2)
        )  # returns the text panel

    def __call__(self, *, ui: UI) -> None:
        """
        pypasscrypt.userinterface.UIPanelDisplay.__call__
        -------------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        # checks if the style is error
        if self.style == "error":
            ui.console.print(self.__show_error())

        # checks if the style is success
        elif self.style == "success":
            ui.console.print(self.__show_success())

        # checks if the style is info
        elif self.style == "info":
            ui.console.print(self.__show_info())

        # checks if the style is warning
        elif self.style == "warning":
            ui.console.print(self.__show_warning())

        # checks if the style is text
        elif self.style == "text":
            ui.console.print(self.__show_text())

        # raises an error if the style is invalid
        else:
            raise ValueError(f'Invalid DisplayStyle {self.style}.')


class UIMessageDisplay(IUIDisplayComponent):
    """
    pypasscrypt.userinterface.UIMessageDisplay
    -----------------------------------------

    A class to handle the user interface messages.

    Example:
    -------
    ```python
    message: UIMessageDisplay = UIMessageDisplay(
        message="This is a message.",
        style="info"
    )
    message(ui=ui)
    ```

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            message: str,
            style: DisplayStyle = "text"
    ) -> None:
        """
        pypasscrypt.userinterface.UIMessageDisplay.__init__
        --------------------------------------------------

        Initialize the UIMessage object.

        :param message: The message to display to the user.
        :param style: The style of the message.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        self.message: str = message
        self.style: DisplayStyle = style

    def __show_error(self) -> str:
        """
        pypasscrypt.userinterface.UIMessageDisplay.__show_error
        -----------------------------------------------------

        Display an error message to the user.

        :return: str

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return f"[bold red]{self.message}[/bold red]"

    def __show_success(self) -> str:
        """
        pypasscrypt.userinterface.UIMessageDisplay.__show_success
        -------------------------------------------------------

        Display a success message to the user.

        :return: str

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return f"[bold green]{self.message}[/bold green]"

    def __show_info(self) -> str:
        """
        pypasscrypt.userinterface.UIMessageDisplay.__show_info
        ----------------------------------------------------

        Display an informational message to the user.

        :return: str

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return f"[bold blue]{self.message}[/bold blue]"

    def __show_warning(self) -> str:
        """
        pypasscrypt.userinterface.UIMessageDisplay.__show_warning
        -------------------------------------------------------

        Display a warning message to the user.

        :return: str

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return f"[bold yellow]{self.message}[/bold yellow]"

    def __show_text(self) -> str:
        """
        pypasscrypt.userinterface.UIMessageDisplay.__show_text
        ----------------------------------------------------

        Display a text message to the user.

        :return: str

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return f"[bold cyan]{self.message}[/bold cyan]"

    def __call__(self, *, ui: UI) -> None:
        """
        pypasscrypt.userinterface.UIMessageDisplay.__call__
        ---------------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        # checks if the style is error
        if self.style == "error":
            ui.console.print(self.__show_error())

        # checks if the style is success
        elif self.style == "success":
            ui.console.print(self.__show_success())

        # checks if the style is info
        elif self.style == "info":
            ui.console.print(self.__show_info())

        # checks if the style is warning
        elif self.style == "warning":
            ui.console.print(self.__show_warning())

        # checks if the style is text
        elif self.style == "text":
            ui.console.print(self.__show_text())

        # raises an error if the style is invalid
        else:
            raise ValueError(f'Invalid DisplayStyle {self.style}.')


class UINotificationDisplay(UIMessageDisplay):
    """
    pypasscrypt.userinterface.UINotificationDisplay
    ----------------------------------------------

    A class to handle the user interface notifications.

    Example:
    -------
    ```python
    notification: UINotificationDisplay = UINotificationDisplay(
        message="This is a notification.",
        style="info",
        delay=1
    )
    notification(ui=ui)

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            message: str,
            style: DisplayStyle = "text",
            delay: int = 1
    ) -> None:
        """
        pypasscrypt.userinterface.UINotificationDisplay.__init__
        --------------------------------------------------------

        Initialize the UINotification object.

        :param message: The message to display to the user.
        :param style: The style of the message.
        :param delay: The delay before the message disappears.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        super().__init__(message=message, style=style)
        self.message: str = message
        self.style: DisplayStyle = style
        self.delay: int = delay

    def __call__(self, *, ui: UI) -> None:
        """
        pypasscrypt.userinterface.UINotificationDisplay.__call__
        -------------------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        super().__call__(ui=ui)
        ui.sleep(delay=self.delay)
        for _ in range(self.message.count("\n") + 1):
            ui.clear_lines(lines=1)


class UITableDisplay(IUIComponent):
    """
    pypasscrypt.userinterface.UITableDisplay
    ----------------------------------------

    A class to handle the user interface tables.

    Example:
    -------
    ```python
    table: UITableDisplay = UITableDisplay(
        title="Table Title",
        headings=["Heading 1", "Heading 2", "Heading 3"],
        rows=[
            ["Row 1, Column 1", "Row 1, Column 2", "Row 1, Column 3"],
            ["Row 2, Column 1", "Row 2, Column 2", "Row 2, Column 3"]
        ],
        index=True
    )
    table(ui=ui)
    ```

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, title: str, headings: List[str], rows: List[List[str]], index: bool = False) -> None:
        """
        pypasscrypt.userinterface.UITableDisplay.__init__
        ------------------------------------------------

        Initialize the UITable object.

        :param title: The title of the table.
        :param headings: The headings of the table.
        :param rows: The rows for the table.
        :param index: Whether to display an index column.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.title: str = title
        self.headings: List[str] = headings
        self.rows: List[List[str]] = rows
        self.index: bool = index

    def __call__(self, *, ui: UI) -> None:
        """
        pypasscrypt.userinterface.UITableDisplay.__call__
        -------------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        table: Table = Table(title=self.title)
        if self.index:
            table.add_column("No.", justify="center")
        for heading in self.headings:
            table.add_column(heading, justify="center")

        if self.index:
            for i, row in enumerate(self.rows, start=1):
                table.add_row(str(i), *row)
        else:
            for row in self.rows:
                table.add_row(*row)

        ui.console.print(table)


class UITextInput(IUIInputComponent):
    """
    pypasscrypt.userinterface.UITextInput
    -------------------------------------

    A class to handle user input for the Password Manager.

    Example:
    -------
    ```python
    text_input: UITextInput = UITextInput(
        message="Enter the text:",
        default="Default text"
    )
    data: str = text_input(ui=ui)
    ```    

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, message: str, default: Any = "") -> None:
        """
        pypasscrypt.userinterface.UITextInput.__init__
        ----------------------------------------------

        Initialize the UIInput object.

        :param message: The message to display to the user.
        :param default: The default input.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.message: str = message
        self.default: str = default

    def __call__(self, *, ui: UI) -> Any:
        """
        pypasscrypt.userinterface.UITextInput.__call__
        ----------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: The input provided by the user.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return InputPrompt(
            message=self.message,
            default=self.default
        ).execute()


class UISingleSelectionInput(IUIInputComponent):
    """
    pypasscrypt.userinterface.UISingleSelectionInput
    ------------------------------------------------

    A class to handle selection input for the Password Manager.

    Example:
    -------
    ```python
    single_selection_input: UISingleSelectionInput = UISingleSelectionInput(
        message="Select the choice:",
        choices=["Choice 1", "Choice 2", "Choice 3"],
        skip_message="Skip",
        default="Choice 1"
    )
    data: str = single_selection_input(ui=ui)
    ```

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            message: str,
            choices: List[str],
            skip_message: Optional[str] = "",
            default: Optional[str] = None
    ) -> None:
        """
        pypasscrypt.userinterface.UISingleSelectionInput.__init__
        --------------------------------------------------------

        Initialize the UISelection object.

        :param message: The message to display to the user.
        :param choices: The choices to display to the user.
        :param default: The default choice.
        :param skip_message: The message to display for skipping the selection.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.message: str = message
        self.choices: List[str] = choices
        self.skip_message: Optional[str] = skip_message if skip_message else None
        self.default: Optional[str] = default if default else None
        if not self.default:
            self.default = self.skip_message

    def __call__(self, *, ui: UI) -> str:
        """
        pypasscrypt.userinterface.UISingleSelectionInput.__call__
        --------------------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: The input provided by the user.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        data: Optional[str] = None
        while not data:
            local_choices: List[str] = self.choices.copy()
            if self.skip_message:
                local_choices.insert(0, self.skip_message)

            data = ListPrompt(
                message=self.message,
                choices=local_choices,
                border=True,
                default=self.default
            ).execute()

            if not data and not self.skip_message:
                ui.console.print(
                    "[bold red]Selection cannot be empty.[/bold red]")
                data = None
        return data


class UIMultiSelectionInput(IUIInputComponent):
    """
    pypasscrypt.userinterface.UIMultiSelectionInput
    -----------------------------------------------

    A class to handle multiple selection input for the Password Manager.

    Example:
    -------
    ```python
    multi_selection_input: UIMultiSelectionInput = UIMultiSelectionInput(
        message="Select the choices:",
        choices=["Choice 1", "Choice 2", "Choice 3"],
        default=["Choice 1"]
    )
    data: List[str] = multi_selection_input(ui=ui)
    ```

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            message: str,
            choices: List[str],
            default: Optional[List[str]] = None
    ) -> None:
        """
        pypasscrypt.userinterface.UIMultiSelectionInput.__init__
        -------------------------------------------------------

        Initialize the UIMultiSelection object.

        :param message: The message to display to the user.
        :param choices: The choices to display to the user.
        :param default: The default choices.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.message: str = message
        self.choices: List[str] = choices
        self.default: List[str] = default if default else []

    def __call__(self, *, ui: UI) -> List[str]:
        """
        pypasscrypt.userinterface.UIMultiSelectionInput.__call__
        -------------------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: The input provided by the user.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return CheckboxPrompt(
            message=self.message,
            choices=self.choices,
            default=self.default
        ).execute()


class UIConfirmInput(IUIInputComponent):
    """
    pypasscrypt.userinterface.UIConfirmInput
    ---------------------------------------

    A class to handle confirmation input for the Password Manager.

    Example:
    -------
    ```python
    confirm_input: UIConfirmInput = UIConfirmInput(
        message="Are you sure?",
        default=False
    )
    confirm: bool = confirm_input(ui=ui)
    ```

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, message: str, default: bool = False) -> None:
        """
        pypasscrypt.userinterface.UIConfirmInput.__init__
        ------------------------------------------------

        Initialize the UIConfirm object.

        :param message: The message to display to the user.
        :param default: The default input.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.message: str = message
        self.default: bool = default

    def __call__(self, *, ui: UI) -> bool:
        """
        pypasscrypt.userinterface.UIConfirmInput.__call__
        ------------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: The input provided by the user.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return ConfirmPrompt(
            message=self.message,
            default=self.default
        ).execute()


class UITextSuggestionInput(IUIInputComponent):
    """
    pypasscrypt.userinterface.UITextSuggestionInput
    -----------------------------------------------

    A class to handle suggestion input for the Password Manager.

    Example:
    -------
    ```python
    suggestion_input: UITextSuggestionInput = UITextSuggestionInput(
        custom_input_message="Enter the custom input:",
        selection_message="Select the choice:",
        choices=["Choice 1", "Choice 2", "Choice 3"],
        skip_message="Skip",
        default="Choice 1"
    )
    data: str = suggestion_input(ui=ui)
    ```

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            custom_input_message: str,
            selection_message: str,
            choices: List[str],
            skip_message: Optional[str],
            default: Optional[str]
    ) -> None:
        """
        pypasscrypt.userinterface.UITextSuggestionInput.__init__
        ------------------------------------------------------

        Initialize the UITextSuggestion object.

        :param custom_input_message: The message to display for custom input.
        :param selection_message: The message to display for selection.
        :param choices: The choices to display for selection.
        :param skip_message: The message to display for skipping the selection.
        :param default: The default choice.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.custom_input_message: str = custom_input_message
        self.selection_message: str = selection_message
        self.choices: List[str] = choices
        self.skip_message: Optional[str] = skip_message
        self.default: Optional[str] = default

    def __call__(self, *, ui: UI) -> str:
        """
        pypasscrypt.userinterface.UITextSuggestionInput.__call__
        -------------------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: The input provided by the user.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        data: Optional[str] = None
        while (
                not data or  # checks if the data is empty
                (
                        data == self.skip_message and  # checks if the data is the skip message
                        not self.skip_message  # checks if the skip message is not provided
                )
        ):  # loops until the data is not empty or the data is not the skip message

            selection_input: UISingleSelectionInput = UISingleSelectionInput(
                message=self.selection_message,
                choices=self.choices,
                skip_message=self.skip_message
            )
            selection: str = selection_input(ui=ui)

            if selection == self.skip_message:  # checks if the selection is the skip message
                custom_input: UITextInput = UITextInput(
                    message=self.custom_input_message,
                    default=self.default
                )
                data = custom_input(ui=ui)
            else:
                data = selection

        return data


class UIPasswordInput(IUIInputComponent):
    """
    pypasscrypt.userinterface.UIPasswordInput
    ----------------------------------------

    A class to handle password input for the Password Manager.

    Example:
    -------
    ```python
    password_input: UIPasswordInput = UIPasswordInput(
            message="Enter the password:",
            validator=lambda x: len(x) >= 8,
            invalid_message="Password must be at least 8 characters long.")
    password: str = password_input(ui=ui)
    ```

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self,
                 *,
                 message: str,
                 validator: Callable = lambda x: True,
                 invalid_message: str = "Invalid password."
                 ) -> None:
        """
        pypasscrypt.userinterface.UIPasswordInput.__init__
        ------------------------------------------------

        Initialize the UIPassword object.

        :param message: The message to display to the user.
        :param validator: The password validator function.
        :param invalid_message: The message to display for an invalid password.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.message: str = message
        self.validator: Callable = validator
        self.invalid_message: str = invalid_message

    def __call__(self, *, ui: UI) -> str:
        """
        pypasscrypt.userinterface.UIPasswordInput.__call__
        -------------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: The input provided by the user.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        password: str = InputPrompt(
            message=self.message,
            is_password=True,
            validate=self.validator,
            invalid_message=self.invalid_message
        ).execute()
        ui.clear_lines(lines=1)
        return password


class UINewPasswordInput(IUIInputComponent):
    """
    pypasscrypt.userinterface.UINewPasswordInput
    -------------------------------------------

    A class to handle password input for the Password Manager.

    Example:
    -------
    ```python
    password_input: UINewPasswordInput = UINewPasswordInput(
        site="example.com",
        username="example",
        password_generator=generate_password
    )
    password: str = password_input(ui=ui)
    ```

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, site: str, username: str, password_generator: Callable) -> None:
        """
        pypasscrypt.userinterface.UINewPasswordInput.__init__
        ---------------------------------------------------

        Initialize the UIPassword object.

        :param site: The site for which the password is being generated.
        :param username: The username associated with the password.
        :param password_generator: The password generator function.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.site: str = site
        self.username: str = username
        self.password_generator: Callable = password_generator

    def __call__(self, *, ui: UI) -> str:
        """
        pypasscrypt.userinterface.UINewPasswordInput.__call__
        ----------------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: The generated or provided password.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        password: Optional[str] = None  # initializes the password to None

        while not password:
            new_password_input: UIPasswordInput = UIPasswordInput(
                message="Enter the password (Leave empty to generate a password):")
            new_password: str = new_password_input(
                ui=ui)  # inputs the new password

            if new_password:  # checks if the new password is not empty
                confirm_password_input: UIPasswordInput = UIPasswordInput(
                    message="Confirm the password:")
                confirm_password: str = confirm_password_input(
                    ui=ui)  # inputs the new password again

                if new_password != confirm_password:  # checks if the passwords match
                    ui.console.print(
                        "[bold red]Passwords do not match.[/bold red]")
                    password = None
                    continue
                else:  # sets the password to the new password
                    password = new_password
                    continue

            # inputs the length of the password
            length: Optional[int] = None
            while length is None:
                try:
                    length_input: UITextInput = UITextInput(
                        message="Enter the length of the password:", default="15")
                    length = int(length_input(ui=ui))
                    if length <= 0:
                        raise ValueError("Length must be a natural number.")
                except ValueError:
                    ui.console.print(
                        "[bold red]Length must be a natural number.[/bold red]")
                    length = None

            include_upper_input: UIConfirmInput = UIConfirmInput(
                message="Include uppercase letters?", default=True)
            include_lower_input: UIConfirmInput = UIConfirmInput(
                message="Include lowercase letters?", default=True)
            include_numbers_input: UIConfirmInput = UIConfirmInput(
                message="Include numbers?", default=True)
            include_symbols_input: UIConfirmInput = UIConfirmInput(
                message="Include symbols?", default=True)

            include_upper: bool = include_upper_input(ui=ui)
            include_lower: bool = include_lower_input(ui=ui)
            include_numbers: bool = include_numbers_input(ui=ui)
            include_symbols: bool = include_symbols_input(ui=ui)

            try:
                password = self.password_generator(
                    context=[
                        self.site,
                        self.username
                    ],
                    length=length,
                    upper_case=include_upper,
                    lower_case=include_lower,
                    numbers=include_numbers,
                    symbols=include_symbols
                )
            except ValueError as e:
                ui.console.print(f"[bold red]{str(e)}[/bold red]")
                password = None

        return password


class UIMasterPasswordInput(IUIInputComponent):
    """
    pypasscrypt.userinterface.UIMasterPasswordInput
    -----------------------------------------------

    A class to handle master password input for the Password Manager.

    Methods:
    - validate_master_password(): Validate the master password.

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, message: str) -> None:
        """
        pypasscrypt.userinterface.UIMasterPasswordInput.__init__
        -------------------------------------------------------
        
        Initialize the UIMasterPassword object.

        :param message: The message to display to the user.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.message: str = message

    @staticmethod
    def validate_master_password(*, password: str) -> bool:
        """
        pypasscrypt.userinterface.UIMasterPasswordInput.validate_master_password
        -----------------------------------------------------------------------

        Validate the master password.

        :param password: The password to validate.
        :return: True if the password is valid, False otherwise.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        if len(password) < 8:  # checks if the password is at least 8 characters long
            return False

        # checks if the password contains a digit
        if not any(char.isdigit() for char in password):
            return False

        # checks if the password contains an uppercase letter
        if not any(char.isupper() for char in password):
            return False

        # checks if the password contains an uppercase letter
        if not any(char.islower() for char in password):
            return False

        # checks if the password contains a symbol
        if not any(char in punctuation for char in password):
            return False

        return True

    def __call__(self, *, ui: UI) -> str:
        """
        pypasscrypt.userinterface.UIMasterPasswordInput.__call__
        -------------------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: The master password provided by the user.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        master_password_input: UIPasswordInput = UIPasswordInput(
            message=self.message,
            validator=self.validate_master_password,
            invalid_message="The password must contain one uppercase, one lowercase, one symbol, and one digit and " +
                            "must be 8 or more characters"
        )

        return master_password_input(ui=ui)


class UINewMasterPasswordInput(IUIInputComponent):
    """
    pypasscrypt.userinterface.UINewMasterPasswordInput
    -------------------------------------------------

    A class to handle new master password input for the Password Manager.

    Example:
    --------
    ```python
    new_master_password_input: UINewMasterPasswordInput = UINewMasterPasswordInput()
    new_master_password: str = new_master_password_input(ui=ui)
    ```

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            new_password_message: str = "Enter the new master password:",
            confirm_password_message: str = "Confirm the new master password:"
    ) -> None:
        """
        pypasscrypt.userinterface.UINewMasterPasswordInput.__init__
        --------------------------------------------------------

        Initialize the UINewMasterPassword object.

        :param new_password_message: The message to display for the new master password.
        :param confirm_password_message: The message to display for confirming the new master password.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.new_password_message: str = new_password_message
        self.confirm_password_message: str = confirm_password_message

    def __call__(self, *, ui: UI) -> str:
        """
        pypasscrypt.userinterface.UINewMasterPasswordInput.__call__
        ----------------------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: The master password provided by the user.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        password: Optional[str] = None  # initializes the password to None
        while not password:

            # inputs the new master password
            new_master_password_input: UIMasterPasswordInput = UIMasterPasswordInput(
                message=self.new_password_message)
            new_master_password: str = new_master_password_input(
                ui=ui)

            # inputs the new master password again
            confirm_master_password_input: UIMasterPasswordInput = UIMasterPasswordInput(
                message=self.confirm_password_message)
            confirm_master_password: str = confirm_master_password_input(
                ui=ui)

            if new_master_password != confirm_master_password:  # checks if the passwords match
                ui.console.print("[bold red]Passwords do not match.[/bold red]")
                password = None
            else:
                password = new_master_password  # sets the password to the new master password

        return password  # returns the new master password


class UIFileInput(IUIInputComponent):
    """
    pypasscrypt.userinterface.UIFileInput
    -------------------------------------

    A class to handle file input for the Password Manager.

    Example:
    --------
    ```python
    file_input: UIFileInput = UIFileInput(extension="bin", initial_dir="C:/users")
    file_path: str = file_input(ui=ui)
    ```

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, extension: str, initial_dir: str) -> None:
        """
        pypasscrypt.userinterface.UIFileInput.__init__
        ----------------------------------------------

        Initialize the UIFileInput object.

        :param extension: The extension of the file.
        :param initial_dir: The initial directory for the file.
        :return: None

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.extension: str = extension
        self.initial_dir: str = initial_dir

    def __call__(self, *, ui: UI) -> str:
        """
        pypasscrypt.userinterface.UIFileInput.__call__
        ----------------------------------------------

        Display the user interface.

        :param ui: ui to mutate.
        :return: The input provided by the user.

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        data: Optional[str] = None
        while not data:

            data = FilePathPrompt(
                message="Enter the file path (press ENTER for GUI):",
                default="",  # "gui",
                invalid_message="File does not exist. Try again.",
                only_files=True
            ).execute()

            if data == "" or not data:
                data = filedialog.askopenfilename(
                    title="Select a file to import",
                    filetypes=[("PassCrypt Files", f"*.{self.extension}")],
                    initialdir=self.initial_dir
                )

            if not data:
                ui.console.print(
                    "[bold red]File path cannot be empty.[/bold red]")
                data = None
                continue

            extension = os.path.splitext(data)[1]
            if extension != f".{self.extension}":
                ui.console.print(
                    f"[bold red]Invalid file type. Please select a file with the extension " +
                    "'.{self.extension}'.[/bold red]")
                data = None
                continue

            if not isinstance(data, str) or not os.path.exists(data):
                ui.console.print(
                    "[bold red]File does not exist. Try again.[/bold red]")
                data = None
                continue

        return data
