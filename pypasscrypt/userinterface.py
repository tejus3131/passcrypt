"""
# pypasscrypt.userinterface
-------------------------

A module to handle the user interface for the Password Manager.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Interfaces:
----------
- `IUIComponent`: A class to handle the user interface components.
- `IUIDisplayComponent`: A class to handle displaying messages to the user.
- `IUIInputComponent`: A class to handle user input for the Password Manager.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Types:
-----
- `DisplayStyle`: The display style for the user interface.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Exceptions:
-----------
- `InvalidDisplayStyleError`: An exception to handle invalid display styles.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
    'InvalidDisplayStyleError',
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
from rich.live import Live
from rich.align import Align
from rich.table import Table
from rich.panel import Panel
from string import punctuation
from tkinter import filedialog
from rich.layout import Layout
from rich.console import Console
from InquirerPy.prompts.list import ListPrompt
from InquirerPy.prompts.input import InputPrompt
from InquirerPy.prompts.confirm import ConfirmPrompt
from InquirerPy.prompts.filepath import FilePathPrompt
from InquirerPy.prompts.checkbox import CheckboxPrompt
from typing import (
    Dict,
    List,
    Any,
    Literal,
    Optional,
    Callable,
    get_args
)
from abc import (
    ABC,
    abstractmethod
)

from pypasscrypt.passwordhandler import PasswordManagerTypes, InvalidPasswordManagerTypeError, PasswordManagerHandler

DisplayStyle = Literal["error", "success", "info", "warning", "text"]
"""
# pypasscrypt.userinterface.DisplayStyle
--------------------------------------

The display style for the user interface.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Values:
- `error`
- `success`
- `info`
- `warning`
- `text`

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
"""


class InvalidDisplayStyleError(Exception):
    """
    # pypasscrypt.userinterface.InvalidDisplayStyleError
    ---------------------------------------------------

    An exception to handle invalid display styles.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, message: str) -> None:
        """
        # pypasscrypt.userinterface.InvalidDisplayStyleError.__init__
        -----------------------------------------------------------

        Initialize the InvalidDisplayStyleError object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The error message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        super().__init__(message)


class InvalidRenderableComponentError(Exception):
    """
    # pypasscrypt.userinterface.InvalidRenderableComponentError
    ----------------------------------------------------------

    An exception to handle invalid renderable components.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, message: str) -> None:
        """
        # pypasscrypt.userinterface.InvalidRenderableComponentError.__init__
        ------------------------------------------------------------------

        Initialize the InvalidRenderableComponentError object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The error message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        super().__init__(message)


class IUIComponent(ABC):
    """
    # pypasscrypt.userinterface.IUIComponent
    --------------------------------------

    A class to handle the user interface components.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported Interfaces:
    ---------------------
    - `IUIDisplayComponent`
    - `IUIInputComponent`

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @abstractmethod
    def __init__(self, *args, **kwargs) -> None:
        """
        # pypasscrypt.userinterface.IUIComponent.__init__
        ----------------------------------------------

        Initialize the UIComponent object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `*args`: The arguments for the UIComponent.
        - `**kwargs`: The keyword arguments for the UIComponent.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the arguments are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @abstractmethod
    def __call__(self, *args, **kwargs) -> Optional[Any]:
        """
        # pypasscrypt.userinterface.IUIComponent.__call__
        ----------------------------------------------

        Display the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `*args`: The arguments for the UIComponent.
        - `**kwargs`: The keyword arguments for the UIComponent.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: if parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class IUIDisplayComponent(IUIComponent, ABC):
    """
    # pypasscrypt.userinterface.IUIDisplayComponent
    ---------------------------------------------

    A class to handle displaying messages to the user.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Supported Classes:
    ------------------
    - `UIPanelDisplay`
    - `UIMessageDisplay`
    - `UINotificationDisplay`

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @abstractmethod
    def __init__(self, *args, **kwargs) -> None:
        """
        # pypasscrypt.userinterface.IUIDisplayComponent.__init__
        -------------------------------------------------------

        Initialize the UIDisplayComponent object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `*args`: The arguments for the UIComponent.
        - `**kwargs`: The keyword arguments for the UIComponent.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the arguments are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @abstractmethod
    def show_error(self) -> Any:
        """
        # pypasscrypt.userinterface.IUIDisplayComponent.show_error
        ---------------------------------------------------------

        Display an error message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the error message is not a string.

        Returns:
        --------
        The renderable error component.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @abstractmethod
    def show_success(self) -> Any:
        """
        # pypasscrypt.userinterface.IUIDisplayComponent.show_success
        ------------------------------------------------------------

        Display a success message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the error message is not a string.

        Returns:
        --------
        The renderable success component.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @abstractmethod
    def show_info(self) -> Any:
        """
        # pypasscrypt.userinterface.IUIDisplayComponent.show_info
        ---------------------------------------------------------

        Display an informational message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the error message is not a string.

        Returns:
        --------
        The renderable info component.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @abstractmethod
    def show_warning(self) -> Any:
        """
        # pypasscrypt.userinterface.IUIDisplayComponent.show_warning
        ------------------------------------------------------------

        Display a warning message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the error message is not a string.

        Returns:
        --------
        The renderable warning component.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @abstractmethod
    def show_text(self) -> Any:
        """
        # pypasscrypt.userinterface.IUIDisplayComponent.show_text
        --------------------------------------------------------

        Display a text message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the error message is not a string.

        Returns:
        --------
        The renderable error component.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @abstractmethod
    def __call__(self, *args,  **kwargs) -> None:
        """
        # pypasscrypt.userinterface.IUIDisplayComponent.__call__
        -------------------------------------------------------

        Display the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `args`: The arguments for the UIComponent.
        - `kwargs`: The keyword arguments for the UIComponent.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: if parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class IUIInputComponent(IUIComponent, ABC):
    """
    # pypasscrypt.userinterface.IUIInputComponent
    ------------------------------------------

    A class to handle user input for the Password Manager.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    @abstractmethod
    def __init__(self, *args, **kwargs) -> None:
        """
        # pypasscrypt.userinterface.IUIInputComponent.__init__
        ----------------------------------------------

        Initialize the UIInputComponent object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `*args`: The arguments for the UIComponent.
        - `**kwargs`: The keyword arguments for the UIComponent.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the arguments are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass

    @abstractmethod
    def __call__(self, *args, **kwargs) -> Any:
        """
        # pypasscrypt.userinterface.IUIInputComponent.__call__
        ----------------------------------------------------

        Display the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `args`: The arguments for the UIComponent.
        - `kwargs`: The keyword arguments for the UIComponent.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: if parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The input provided by the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        pass


class UI:
    """
    # pypasscrypt.userinterface.UI
    ----------------------------------

    A class to handle the user interface helper functions.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Methods:
    -------
    - `animate()`: Animate a message in the user interface.
    - `render()`: Render a component in the user interface.
    - `print()`: Print a message to the user.
    - `clear_all()`: Clear the terminal screen.
    - `clear_lines()`: Clear the lines in the terminal.
    - `wait()`: Wait for the user to press ENTER.
    - `exit()`: Exit the Password Manager.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Decorators:
    ----------
    - `page()`: Display a page in the user interface.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self) -> None:
        """
        # pypasscrypt.userinterface.UI.__init__
        ------------------------------------------

        Initialize the UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.console: Console = Console()

    def clear_all(self) -> None:
        """
        # pypasscrypt.userinterface.UI.clear_all
        ------------------------------------------------

        Clear the terminal screen.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        self.console.clear()

    def clear_lines(self, *, lines: int) -> None:
        """
        # pypasscrypt.userinterface.UI.clear_lines
        ----------------------------------------------

        Clear the lines in the terminal.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `lines`: The number of lines to clear.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------

        - `TypeError`: If the lines is not an integer.
        - `ValueError`: If the lines is less than 1.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(lines, int):
            raise TypeError("lines must be an integer.")

        if lines < 1:
            raise ValueError("lines must be greater than 0.")
        
        self.console.print("Clearing lines...")

        for _ in range(lines + 1):
            sys.stdout.write('\033[F')  # Move the cursor up one line
            sys.stdout.write('\033[K')  # Clear the line
            sys.stdout.flush()

    def wait(self, *, wait_message: str) -> None:
        """
        # pypasscrypt.userinterface.UI.wait
        ---------------------------------------

        Wait for the user to press ENTER.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `wait_message`: The message to display to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the wait_message is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(wait_message, str):
            raise TypeError("wait_message must be a string.")

        self.console.print(f"\n[bold cyan]{wait_message}[/bold cyan]")
        input()

    def exit(self, *, exit_message: str) -> None:
        """
        # pypasscrypt.userinterface.UI.exit
        ---------------------------------------

        Exit the UI.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `exit_message`: The message to display to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the exit_message is not a string.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(exit_message, str):
            raise TypeError("exit_message must be a string.")
        self.clear_all()

        self.animate(
            message=exit_message,
            title="Exiting",
            wait_time=1.0
        )
        self.clear_all()
        sys.exit(0)

    def page(self, *, title: str, subtitle: str, message: str = "", style: DisplayStyle = "text") -> Callable[..., Any]:
        """
        # pypasscrypt.userinterface.UI.page
        ---------------------------------------

        Display a page in the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `title`: The title of the page.
        - `subtitle`: The subtitle of the page.
        - `message`: The message of the page.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        Wraps the function to display the page.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Example:
        -------

        >>> ui: UI = UI()
        >>> @ui.page(title="Page Title", subtitle="Page Subtitle")
        >>> def display_page() -> None:
        >>>     ui.console.print("This is a page.")
        >>> display_page()

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(title, str):
            raise TypeError("title must be a string.")

        if not isinstance(subtitle, str):
            raise TypeError("subtitle must be a string.")
        
        if not isinstance(message, str):
            raise TypeError("message must be a string.")

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            """
            # pypasscrypt.userinterface.UI.page.<decorator>
            ---------------------------------------------------

            Decorator to wrap the function.

            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

            Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
            """

            def wrapper(*args, **kwargs) -> Any:
                """
                # pypasscrypt.userinterface.UI.page.<decorator>.<wrapper>
                ----------------------------------------------------------------

                Wrapper function to display the page.

                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

                Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
                """
                self.clear_all()
                navbar = UIPanelDisplay(
                    title=title,
                    subtitle=subtitle,
                    message=message,
                    style=style
                )
                self.render(component=navbar)
                self.console.print("\n")
                return func(*args, **kwargs)

            return wrapper

        return decorator
    
    def print(self, *, message: str, style: DisplayStyle = "text") -> None:
        """
        # pypasscrypt.userinterface.UI.print
        ---------------------------------------

        Print a message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to print.
        - `style`: The style of the message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the message is not a string.
        - `InvalidDisplayStyleError`: If the style is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(message, str):
            raise TypeError("message must be a string.")
        
        if style not in get_args(DisplayStyle):
            raise InvalidDisplayStyleError(f'Invalid DisplayStyle {style}.') from ValueError(style)
        
        if style == "error":
            self.console.print(f"[bold red]{message}[/bold red]")
            
        elif style == "success":
            self.console.print(f"[bold green]{message}[/bold green]")

        elif style == "info":
            self.console.print(f"[bold blue]{message}[/bold blue]")

        elif style == "warning":
            self.console.print(f"[bold yellow]{message}[/bold yellow]")

        elif style == "text":
            self.console.print(f"[bold cyan]{message}[/bold cyan]")
    
    def animate(
            self,
            *,
            message: str,
            title: str,
            wait_time: float = 1.0,
            border_style: str = "magenta",
    ) -> None:
        """
        # pypasscrypt.userinterface.UI.animate
        ---------------------------------------

        Animate a message in the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to animate.
        - `title`: The title of the animation.
        - `wait_time`: The time to wait between animations.
        - `border_style`: The border style of the message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(message, str):
            raise TypeError("message must be a string.")

        if not isinstance(border_style, str):
            raise TypeError("border_style must be a string.")

        if not isinstance(title, str):
            raise TypeError("title must be a string.")

        max_length = len(message)
            
        layout = Layout()

        layout.split(
            Layout(name="main", ratio=1)
        )

        with Live(layout, refresh_per_second=60, screen=True, console=self.console) as live:
                
            for i in range(max_length + 1):
                display_text = message[:i]
                layout["main"].update(
                    Panel(
                        Align.center(display_text, vertical="middle"), 
                        border_style=border_style, 
                        expand=True, 
                        title=title
                        )
                )
                live.update(layout)
                sleep(0.04)

            sleep(wait_time)
            
            for i in range(max_length, -1, -1):
                display_text = message[:i]
                layout["main"].update(
                    Panel(
                        Align.center(display_text, vertical="middle"), 
                        border_style=border_style, 
                        expand=True, 
                        title=title
                        )
                )
                live.update(layout)
                sleep(0.04)

    def render(self, *, component: IUIComponent) -> Any:
        """
        # pypasscrypt.userinterface.UI.render
        ---------------------------------------

        Render a component in the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `component`: The component to render.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(component, IUIComponent):
            raise TypeError("component must be an IUIComponent object.")
        
        if isinstance(component, IUIComponent):
            return component(ui=self)
        else:
            raise InvalidRenderableComponentError(f'Invalid Renderable Component type: {type(component)}.')


class UIPanelDisplay(IUIDisplayComponent):
    """
    # pypasscrypt.userinterface.UIPanelDisplay
    ----------------------------------------

    A class to handle the user interface panels.

    Example:
    -------
    >>> ui: UI = UI()
    >>> panel: UIPanelDisplay = UIPanelDisplay(
    >>>     title="Panel Title",
    >>>     subtitle="Panel Subtitle",
    >>>     message="Panel Message"     
    >>> )
    >>> ui.render(component=panel)

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
        # pypasscrypt.userinterface.UIPanelDisplay.__init__
        ------------------------------------------------

        Initialize the UIPanel object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `title`: The title of the panel.
        - `subtitle`: The subtitle of the panel.
        - `message`: The message of the panel.
        - `style`: The style of the panel.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(title, str):
            raise TypeError("title must be a string.")

        if not isinstance(subtitle, str):
            raise TypeError("subtitle must be a string.")

        if not isinstance(message, str):
            raise TypeError("message must be a string.")
        
        if style not in get_args(DisplayStyle):
            raise InvalidDisplayStyleError(f'Invalid DisplayStyle {style}.') from ValueError(style)

        self.title: str = title  # sets the title of the panel
        self.subtitle: str = subtitle  # sets the subtitle of the panel
        self.message: str = message  # sets the message of the panel
        self.style: DisplayStyle = style  # sets the style of the panel

    def show_error(self) -> Panel:
        """
        # pypasscrypt.userinterface.UIPanelDisplay.show_error
        ----------------------------------------------------

        Display an error message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The error panel.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

    def show_success(self) -> Panel:
        """
        # pypasscrypt.userinterface.UIPanelDisplay.show_success
        ----------------------------------------------------

        Display an success message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The success panel.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

    def show_info(self) -> Panel:
        """
        # pypasscrypt.userinterface.UIPanelDisplay.show_info
        ----------------------------------------------------

        Display an info message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The info panel.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

    def show_warning(self) -> Panel:
        """
        # pypasscrypt.userinterface.UIPanelDisplay.show_warning
        ----------------------------------------------------

        Display an warning message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The warning panel.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

    def show_text(self) -> Panel:
        """
        # pypasscrypt.userinterface.UIPanelDisplay.show_text
        ----------------------------------------------------

        Display a text message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The text panel.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
        # pypasscrypt.userinterface.UIPanelDisplay.__call__
        -------------------------------------------------

        Display the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ui`: The UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the ui is not a UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(ui, UI):
            raise TypeError("ui must be a UI object.")

        # checks if the style is error
        if self.style == "error":
            ui.console.print(self.show_error())

        # checks if the style is success
        elif self.style == "success":
            ui.console.print(self.show_success())

        # checks if the style is info
        elif self.style == "info":
            ui.console.print(self.show_info())

        # checks if the style is warning
        elif self.style == "warning":
            ui.console.print(self.show_warning())

        # checks if the style is text
        elif self.style == "text":
            ui.console.print(self.show_text())


class UIMessageDisplay(IUIDisplayComponent):
    """
    # pypasscrypt.userinterface.UIMessageDisplay
    -----------------------------------------

    A class to handle the user interface messages.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Example:
    -------
    >>> ui: UI = UI()
    >>> message: UIMessageDisplay = UIMessageDisplay(
    >>>     message="This is a message."
    >>> )
    >>> ui.render(component=message)

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            message: str,
            style: DisplayStyle = "text"
    ) -> None:
        """
        # pypasscrypt.userinterface.UIMessageDisplay.__init__
        --------------------------------------------------

        Initialize the UIMessage object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to display to the user.
        - `style`: The style of the message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the message is not a string.
        - `InvalidDisplayStyleError`: If the style is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(message, str):
            raise TypeError("message must be a string.")
        
        if style not in get_args(DisplayStyle):
            raise InvalidDisplayStyleError(f'Invalid DisplayStyle {style}.') from ValueError(style)

        self.message: str = message
        self.style: DisplayStyle = style

    def show_error(self) -> str:
        """
        # pypasscrypt.userinterface.UIMessageDisplay.show_error
        -----------------------------------------------------

        Display an error message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The error message renderable.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return f"[bold red]{self.message}[/bold red]"

    def show_success(self) -> str:
        """
        # pypasscrypt.userinterface.UIMessageDisplay.show_success
        -------------------------------------------------------

        Display a success message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The success message renderable.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return f"[bold green]{self.message}[/bold green]"

    def show_info(self) -> str:
        """
        # pypasscrypt.userinterface.UIMessageDisplay.show_info
        ----------------------------------------------------

        Display an informational message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The info message renderable.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return f"[bold blue]{self.message}[/bold blue]"

    def show_warning(self) -> str:
        """
        # pypasscrypt.userinterface.UIMessageDisplay.show_warning
        -------------------------------------------------------

        Display a warning message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The warning message renderable.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return f"[bold yellow]{self.message}[/bold yellow]"

    def show_text(self) -> str:
        """
        # pypasscrypt.userinterface.UIMessageDisplay.show_text
        ----------------------------------------------------

        Display a text message to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The text message renderable.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return f"[bold cyan]{self.message}[/bold cyan]"

    def __call__(self, *, ui: UI) -> None:
        """
        # pypasscrypt.userinterface.UIMessageDisplay.__call__
        ---------------------------------------------------

        Display the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ui`: The UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the style is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(ui, UI):
            raise TypeError("ui must be a UI object.")

        # checks if the style is error
        if self.style == "error":
            ui.console.print(self.show_error())

        # checks if the style is success
        elif self.style == "success":
            ui.console.print(self.show_success())

        # checks if the style is info
        elif self.style == "info":
            ui.console.print(self.show_info())

        # checks if the style is warning
        elif self.style == "warning":
            ui.console.print(self.show_warning())

        # checks if the style is text
        elif self.style == "text":
            ui.console.print(self.show_text())


class UINotificationDisplay(UIMessageDisplay):
    """
    # pypasscrypt.userinterface.UINotificationDisplay
    ----------------------------------------------

    A class to handle the user interface notifications.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Example:
    -------
    >>> ui: UI = UI()
    >>> notification: UINotificationDisplay = UINotificationDisplay(
    >>>     message="This is a notification.",
    >>>     delay=1
    >>> )
    >>> ui.render(component=notification)

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
        # pypasscrypt.userinterface.UINotificationDisplay.__init__
        --------------------------------------------------------

        Initialize the UINotification object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to display to the user.
        - `style`: The style of the notification.
        - `delay`: The delay in seconds.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.
        - `InvalidDisplayStyleError`: If the style is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(message, str):
            raise TypeError("message must be a string.")
        
        if style not in get_args(DisplayStyle):
            raise InvalidDisplayStyleError(f'Invalid DisplayStyle {style}.') from ValueError(style)

        if not isinstance(delay, int):
            raise TypeError("delay must be an integer.")

        super().__init__(message=message)
        self.message: str = message
        self.style: DisplayStyle = style
        self.delay: int = delay

    def __call__(self, *, ui: UI) -> None:
        """
        # pypasscrypt.userinterface.UINotificationDisplay.__call__
        -------------------------------------------------------

        Display the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `style`: The style of the notification.
        - `ui`: The UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the style is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(ui, UI):
            raise TypeError("ui must be a UI object.")

        super().__call__(ui=ui)
        sleep(self.delay)
        for _ in range(self.message.count("\n") + 1):
            ui.clear_lines(lines=1)


class UITableDisplay(IUIComponent):
    """
    # pypasscrypt.userinterface.UITableDisplay
    ----------------------------------------

    A class to handle the user interface tables.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Example:
    -------
    >>> ui: UI = UI()
    >>> table: UITableDisplay = UITableDisplay(
    >>>     title="Table Title",
    >>>     headings=["Heading 1", "Heading 2", "Heading 3"],
    >>>     rows=[
    >>>         ["Row 1, Column 1", "Row 1, Column 2", "Row 1, Column 3"],
    >>>         ["Row 2, Column 1", "Row 2, Column 2", "Row 2, Column 3"]
    >>>     ],
    >>>     index=True
    >>> )
    >>> ui.render(component=table)

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, title: str, headings: List[str], rows: List[List[str]], index: bool = False) -> None:
        """
        # pypasscrypt.userinterface.UITableDisplay.__init__
        ------------------------------------------------

        Initialize the UITable object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `title`: The title of the table.
        - `headings`: The headings of the table.
        - `rows`: The rows of the table.
        - `index`: Display the index.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(title, str):
            raise TypeError("title must be a string.")

        if not isinstance(headings, list):
            raise TypeError("headings must be a list.")
        else:
            for heading in headings:
                if not isinstance(heading, str):
                    raise TypeError("headings must be a list of strings.")

        if not isinstance(rows, list):
            raise TypeError("rows must be a list.")
        else:
            for row in rows:
                if not isinstance(row, list):
                    raise TypeError("rows must be a list of lists.")
                else:
                    for column in row:
                        if not isinstance(column, str):
                            raise TypeError(
                                "rows must be a list of lists of strings.")
                        
        if not isinstance(index, bool):
            raise TypeError("index must be a boolean.")

        self.title: str = title
        self.headings: List[str] = headings
        self.rows: List[List[str]] = rows
        self.index: bool = index

    def __call__(self, *, ui: UI) -> None:
        """
        # pypasscrypt.userinterface.UITableDisplay.__call__
        -------------------------------------------------

        Display the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ui`: The UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(ui, UI):
            raise TypeError("ui must be a UI object.")

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
    # pypasscrypt.userinterface.UITextInput
    -------------------------------------

    A class to handle user input for the Password Manager.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Example:
    -------
    >>> ui: UI = UI()
    >>> text_input: UITextInput = UITextInput(
    >>>     message="Enter the text:",
    >>>     default="Default text"
    >>> )
    >>> data: str = ui.render(component=text_input)   

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            message: str,
            default: Optional[str] = None,
            allow_empty: bool = False,
            empty_error_message: str = "Please provide a valid input."
    ) -> None:
        """
        # pypasscrypt.userinterface.UITextInput.__init__
        ----------------------------------------------

        Initialize the UIInput object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to display to the user.
        - `default`: The default text.
        - `allow_empty`: Allow empty input.
        - `empty_error_message`: The error message for empty input.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(message, str):
            raise TypeError("message must be a string.")

        if not isinstance(default, str) and default is not None:
            raise TypeError("default must be a string or None.")

        if not isinstance(allow_empty, bool):
            raise TypeError("allow_empty must be a boolean.")

        if not isinstance(empty_error_message, str):
            raise TypeError("empty_error_message must be a string.")

        self.message: str = message
        self.default: str = default if default else ""
        self.allow_empty: bool = allow_empty
        self.empty_error_message: str = empty_error_message

    def __call__(self, *, ui: UI) -> Optional[str]:
        """
        # pypasscrypt.userinterface.UITextInput.__call__
        ----------------------------------------------

        Display the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ui`: The UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The input provided by the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(ui, UI):
            raise TypeError("ui must be a UI object.")

        data: Optional[str] = None

        while not data:
            data = InputPrompt(
                message=self.message,
                default=self.default
            ).execute()

            if not data or data.isspace() or data == "":
                data = None
                if self.allow_empty:
                    break
                else:
                    ui.render(component=UINotificationDisplay(message=self.empty_error_message, delay=1, style="error"))

        return str(data) if data else None


class UISingleSelectionInput(IUIInputComponent):
    """
    # pypasscrypt.userinterface.UISingleSelectionInput
    ------------------------------------------------

    A class to handle selection input for the Password Manager.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Example:
    -------
    >>> ui: UI = UI()
    >>> single_selection_input: UISingleSelectionInput = UISingleSelectionInput(
    >>>     message="Select the choice:",
    >>>     choices=["Choice 1", "Choice 2", "Choice 3"],
    >>>     skip_message="Skip",
    >>>     default="Choice 1"
    >>> )
    >>> data: str = ui.render(component=single_selection_input)

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            message: str,
            choices: List[str],
            skip_message: Optional[str] = None,
            default: Optional[str] = None
    ) -> None:
        """
        # pypasscrypt.userinterface.UISingleSelectionInput.__init__
        --------------------------------------------------------

        Initialize the UISelection object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to display to the user.
        - `choices`: The choices to display to the user.
        - `skip_message`: The skip message.
        - `default`: The default choice.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(message, str):
            raise TypeError("message must be a string.")

        if not isinstance(choices, list):
            raise TypeError("choices must be a list.")
        else:
            for choice in choices:
                if not isinstance(choice, str):
                    raise TypeError("choices must be a list of strings.")

        if not isinstance(skip_message, str) and skip_message is not None:
            raise TypeError("skip_message must be a string.")

        if not isinstance(default, str) and default is not None:
            raise TypeError("default must be a string or None.")
        self.message: str = message
        self.choices: List[str] = choices
        self.skip_message: Optional[str] = skip_message if skip_message else None
        self.default: Optional[str] = default if default else None
        if not self.default:
            self.default = self.skip_message

    def __call__(self, *, ui: UI) -> Optional[str]:
        """
        # pypasscrypt.userinterface.UISingleSelectionInput.__call__
        --------------------------------------------------------

        Display the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ui`: The UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the ui is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The input provided by the user. None if the user skips.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(ui, UI):
            raise TypeError("ui must be a UI object.")

        local_choices: List[str] = self.choices.copy()

        if self.skip_message:
            local_choices.insert(0, self.skip_message)

        data = ListPrompt(
            message=self.message,
            choices=local_choices,
            border=True,
            default=self.default if self.default else local_choices[0]
        ).execute()
        
        if data == self.skip_message:
            return None
        
        return data


class UIMultiSelectionInput(IUIInputComponent):
    """
    # pypasscrypt.userinterface.UIMultiSelectionInput
    -----------------------------------------------

    A class to handle multiple selection input for the Password Manager.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Example:
    -------
    >>> ui: UI = UI()
    >>> multi_selection_input: UIMultiSelectionInput = UIMultiSelectionInput(
    >>>     message="Select the choices:",
    >>>     choices=["Choice 1", "Choice 2", "Choice 3"],
    >>>     default=["Choice 1"]
    >>> )
    >>> data: List[str] = ui.render(component=multi_selection_input)

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            message: str,
            choices: List[str],
            default: Optional[List[str]] = None,
            allow_empty: bool = False,
            empty_error_message: str = "Please select at least one choice."
    ) -> None:
        """
        # pypasscrypt.userinterface.UIMultiSelectionInput.__init__
        -------------------------------------------------------

        Initialize the UIMultiSelection object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to display to the user.
        - `choices`: The choices to display to the user.
        - `default`: The default choices.
        - `allow_empty`: Allow empty input.
        - `empty_error_message`: The error message for empty input.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(message, str):
            raise TypeError("message must be a string.")

        if not isinstance(choices, list):
            raise TypeError("choices must be a list.")
        else:
            for choice in choices:
                if not isinstance(choice, str):
                    raise TypeError("choices must be a list of strings.")

        if isinstance(default, list):
            for choice in default:
                if not isinstance(choice, str):
                    raise TypeError("default must be a list of strings.")
        elif default is not None:
            raise TypeError("default must be a list or None")

        if not isinstance(allow_empty, bool):
            raise TypeError("allow_empty must be a boolean.")

        if not isinstance(empty_error_message, str):
            raise TypeError("empty_error_message must be a string.")

        self.message: str = message
        self.choices: List[str] = choices
        self.default: List[str] = default if default else []
        self.allow_empty: bool = allow_empty
        self.empty_error_message: str = empty_error_message

    def __call__(self, *, ui: UI) -> Optional[List[str]]:
        """
        # pypasscrypt.userinterface.UIMultiSelectionInput.__call__
        -------------------------------------------------------

        Display the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ui`: The UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the ui is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The input provided by the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        data: Optional[List[str]] = None
        while not data:

            data = CheckboxPrompt(
                message=self.message,
                choices=self.choices,
                default=self.default
            ).execute()

            if not data or len(data) == 0:
                data = None
                if not self.allow_empty:
                    ui.render(component=UINotificationDisplay(message=self.empty_error_message, delay=1, style="error"))
                else:
                    break

        return data


class UIConfirmInput(IUIInputComponent):
    """
    # pypasscrypt.userinterface.UIConfirmInput
    ---------------------------------------

    A class to handle confirmation input for the Password Manager.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Example:
    -------
    >>> ui: UI = UI()
    >>> confirm_input: UIConfirmInput = UIConfirmInput(
    >>>     message="Are you sure?",
    >>>     default=False
    >>> )
    >>> confirm: bool = ui.render(component=confirm_input)

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, message: str, default: Optional[bool] = None) -> None:
        """
        # pypasscrypt.userinterface.UIConfirmInput.__init__
        ------------------------------------------------

        Initialize the UIConfirm object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to display to the user.
        - `default`: The default choice.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(message, str):
            raise TypeError("message must be a string.")

        if not isinstance(default, bool) and default is not None:
            raise TypeError("default must be a boolean or None.")

        self.message: str = message
        self.default: bool = default if default else False

    def __call__(self, *, ui: UI) -> bool:
        """
        # pypasscrypt.userinterface.UIConfirmInput.__call__
        ------------------------------------------------

        Display the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ui`: The UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The input provided by the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        return ConfirmPrompt(
            message=self.message,
            default=self.default
        ).execute()


class UITextSuggestionInput(IUIInputComponent):
    """
    # pypasscrypt.userinterface.UITextSuggestionInput
    -----------------------------------------------

    A class to handle suggestion input for the Password Manager.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Example:
    -------
    >>> ui: UI = UI()
    >>> suggestion_input: UITextSuggestionInput = UITextSuggestionInput(
    >>>     custom_input_message="Enter the custom input:",
    >>>     selection_message="Select the choice:",
    >>>     choices=["Choice 1", "Choice 2", "Choice 3"],
    >>>     skip_message="Skip"
    >>> )
    >>> data: str = ui.render(component=suggestion_input)

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            custom_input_message: str,
            selection_message: str,
            choices: List[str],
            skip_message: str,
            default: Optional[str] = None,
            allow_empty: bool = False,
            empty_error_message: str = "Please provide a valid input."
    ) -> None:
        """
        # pypasscrypt.userinterface.UITextSuggestionInput.__init__
        ------------------------------------------------------

        Initialize the UITextSuggestion object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `custom_input_message`: The custom input message.
        - `selection_message`: The selection message.
        - `choices`: The choices to display to the user.
        - `skip_message`: The skip message.
        - `default`: The default choice.
        - `allow_empty`: Allow empty input.
        - `empty_error_message`: The error message for empty input.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(custom_input_message, str):
            raise TypeError("custom_input_message must be a string.")

        if not isinstance(selection_message, str):
            raise TypeError("selection_message must be a string.")

        if not isinstance(choices, list):
            raise TypeError("choices must be a list.")
        else:
            for choice in choices:
                if not isinstance(choice, str):
                    raise TypeError("choices must be a list of strings.")

        if not isinstance(skip_message, str):
            raise TypeError("skip_message must be a string.")

        if not isinstance(default, str) and default is not None:
            raise TypeError("default must be a string or None.")

        if not isinstance(allow_empty, bool):
            raise TypeError("allow_empty must be a boolean.")

        if not isinstance(empty_error_message, str):
            raise TypeError("empty_error_message must be a string.")

        self.custom_input_message: str = custom_input_message
        self.selection_message: str = selection_message
        self.choices: List[str] = choices
        self.skip_message: str = skip_message
        self.default: Optional[str] = default if default else None
        self.allow_empty: bool = allow_empty
        self.empty_error_message: str = empty_error_message

        if not self.default:
            self.default = self.skip_message

    def __call__(self, *, ui: UI) -> Optional[str]:
        """
        # pypasscrypt.userinterface.UITextSuggestionInput.__call__
        -------------------------------------------------------

        Display the user interface.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ui`: The UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The input provided by the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        data: Optional[str] = None

        while not data:

            if len(self.choices) < 1:

                data = InputPrompt(
                    message=self.custom_input_message,
                    raise_keyboard_interrupt=True
                ).execute()

                if not data or data.isspace() or data == "":
                    data = None
                    if self.allow_empty:
                        return None
                    else:
                        ui.render(component=UINotificationDisplay(
                            message=self.empty_error_message, delay=1, style="error"))
                        ui.clear_lines(lines=1)

            else:

                selection_input: UISingleSelectionInput = UISingleSelectionInput(
                    message=self.selection_message,
                    choices=self.choices,
                    skip_message=self.skip_message,
                    default=self.default
                )
                selection: Optional[str] = selection_input(ui=ui)

                if selection:
                    return selection
                
                input_data: Optional[str] = None

                while not input_data:
                    try:
                        input_data = InputPrompt(
                            message=self.custom_input_message +
                            " (press ctrl+c for selection menu)",
                            raise_keyboard_interrupt=True
                        ).execute()
                    except KeyboardInterrupt:
                        ui.clear_lines(lines=2)
                        input_data = "None"
                        continue

                    if not input_data or input_data.isspace() or input_data == "":
                        input_data = None
                        if self.allow_empty:
                            return None
                        else:
                            ui.render(component=UINotificationDisplay(
                                message=self.empty_error_message, delay=1, style="error"))
                            ui.clear_lines(lines=1)

                    else:
                        data = input_data                

        return str(data)


class UIPasswordInput(IUIInputComponent):
    """
    # pypasscrypt.userinterface.UIPasswordInput
    ----------------------------------------

    A class to handle password input for the Password Manager.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Example:
    -------
    >>> ui: UI = UI()
    >>> password_input: UIPasswordInput = UIPasswordInput(
    >>>         message="Enter the password:",
    >>>         validator=lambda x: len(x) >= 8,
    >>>         invalid_message="Password must be at least 8 characters long.")
    >>> password: str = ui.render(component=password_input)

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            message: str,
            validator: Callable = lambda x: True,
            invalid_message: str = "Invalid password."
    ) -> None:
        """
        # pypasscrypt.userinterface.UIPasswordInput.__init__
        ------------------------------------------------

        Initialize the UIPassword object.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to display to the user.
        - `validator`: The password validator function.
        - `invalid_message`: The invalid password message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(message, str):
            raise TypeError("message must be a string.")
        
        if not callable(validator):
            raise TypeError("validator must be a function.")
        
        if not isinstance(invalid_message, str):
            raise TypeError("invalid_message must be a string.")

        self.message: str = message
        self.validator: Callable = validator
        self.invalid_message: str = invalid_message

    def __call__(self, *, ui: UI) -> str:
        """
        # pypasscrypt.userinterface.UIPasswordInput.__call__
        -------------------------------------------------

        Display the user interface.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ui`: The UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The input provided by the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
    # pypasscrypt.userinterface.UINewPasswordInput
    -------------------------------------------

    A class to handle password input for the Password Manager.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Example:
    -------
    >>> ui: UI = UI()
    >>> generate_password: Callable = lambda x: True
    >>> password_input: UINewPasswordInput = UINewPasswordInput(
    >>>     site="example.com",
    >>>     username="example",
    >>>     password_generator=generate_password
    >>> )
    >>> password: str = ui.render(component=password_input)

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self, 
            *,
            password_generator_type: PasswordManagerTypes,
            allow_upper_case: bool,
            allow_lower_case: bool,
            allow_numbers: bool,
            allow_symbols: bool,
            allow_similar: bool,
            length: int,
            context: List[str],
            context_filter: List[str],
            similar_characters: Dict[str, str]
    ) -> None:
        """
        # pypasscrypt.userinterface.UINewPasswordInput.__init__
        ---------------------------------------------------

        Initialize the UIPassword object.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `password_generator_type`: The password generator type.
        - `allow_upper_case`: Allow uppercase letters.
        - `allow_lower_case`: Allow lowercase letters.
        - `allow_numbers`: Allow numbers.
        - `allow_symbols`: Allow symbols.
        - `allow_similar`: Allow similar characters.
        - `length`: The length of the password.
        - `context`: The context for the password.
        - `context_filter`: The context filter for the password.
        - `similar_characters`: The similar characters.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """
        
        if password_generator_type not in get_args(PasswordManagerTypes):
            raise InvalidPasswordManagerTypeError(f'Invalid PasswordManagerType {password_generator_type}.') from ValueError(password_generator_type)
        
        if not isinstance(allow_upper_case, bool):
            raise TypeError("allow_upper_case must be a boolean.")
        
        if not isinstance(allow_lower_case, bool):
            raise TypeError("allow_lower_case must be a boolean.")
        
        if not isinstance(allow_numbers, bool):
            raise TypeError("allow_numbers must be a boolean.")
        
        if not isinstance(allow_symbols, bool):
            raise TypeError("allow_symbols must be a boolean.")
        
        if not isinstance(allow_similar, bool):
            raise TypeError("allow_similar must be a boolean.")
        
        if not isinstance(length, int):
            raise TypeError("length must be an integer.")
        
        if not isinstance(context, list):
            raise TypeError("context must be a list.")
        else:
            for c in context:
                if not isinstance(c, str):
                    raise TypeError("context must be a list of strings.")
        
        if not isinstance(context_filter, list):
            raise TypeError("context_filter must be a list.")
        else:
            for c in context_filter:
                if not isinstance(c, str):
                    raise TypeError("context_filter must be a list of strings.")
                
        if not isinstance(similar_characters, dict):
            raise TypeError("similar_characters must be a dictionary.")
        else:
            for key, value in similar_characters.items():
                if not isinstance(key, str):
                    raise TypeError("similar_characters must be a dictionary of strings.")
                if not isinstance(value, str):
                    raise TypeError("similar_characters must be a dictionary of strings.")
                
        self.password_generator_type: PasswordManagerTypes = password_generator_type
        self.allow_upper_case: bool = allow_upper_case
        self.allow_lower_case: bool = allow_lower_case
        self.allow_numbers: bool = allow_numbers
        self.allow_symbols: bool = allow_symbols
        self.allow_similar: bool = allow_similar
        self.length: int = length
        self.context: List[str] = context
        self.context_filter: List[str] = context_filter
        self.similar_characters: Dict[str, str] = similar_characters

    def __call__(self, *, ui: UI) -> str:
        """
        # pypasscrypt.userinterface.UINewPasswordInput.__call__
        ----------------------------------------------------

        Display the user interface.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ui`: The UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the ui is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The input provided by the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(ui, UI):
            raise TypeError("ui must be a UI object.")

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

            try:
                password = PasswordManagerHandler.generate_password(
                    context_list=self.context,
                    context_filters=self.context_filter,
                    length=self.length,
                    upper_case_allowed=self.allow_upper_case,
                    lower_case_allowed=self.allow_lower_case,
                    digits_allowed=self.allow_numbers,
                    symbols_allowed=self.allow_symbols,
                    swipe_similar_characters=self.allow_similar,
                    similar_characters=self.similar_characters,
                    password_manager_type=self.password_generator_type
                )
            except ValueError as e:
                ui.render(component=UINotificationDisplay(
                    message=str(e),
                    delay=1,
                    style="error"
                ))
                password = None

        return password


class UIMasterPasswordInput(IUIInputComponent):
    """
    # pypasscrypt.userinterface.UIMasterPasswordInput
    -----------------------------------------------

    A class to handle master password input for the Password Manager.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    Example:
    -------
    >>> ui: UI = UI()
    >>> master_password_input: UIMasterPasswordInput = UIMasterPasswordInput(
    >>>     message="Enter the master password:"
    >>> )
    >>> master_password: str = ui.render(component=master_password_input)

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, message: str) -> None:
        """
        # pypasscrypt.userinterface.UIMasterPasswordInput.__init__
        -------------------------------------------------------

        Initialize the UIMasterPassword object.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `message`: The message to display to the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(message, str):
            raise TypeError("message must be a string.")

        self.message: str = message

    @staticmethod
    def validate_master_password(password: str) -> bool:
        """
        # pypasscrypt.userinterface.UIMasterPasswordInput.validate_master_password
        -----------------------------------------------------------------------

        Validate the master password.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `password`: The password to validate.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the password is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        True if the password is valid, False otherwise.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(password, str):  # checks if the password is a string
            raise TypeError("password must be a string.")

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
        # pypasscrypt.userinterface.UIMasterPasswordInput.__call__
        -------------------------------------------------------

        Display the user interface.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ui`: The UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the ui is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The input provided by the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(ui, UI):  # checks if the ui is a UI object
            raise TypeError("ui must be a UI object.")

        master_password_input: UIPasswordInput = UIPasswordInput(
            message=self.message,
            validator=self.validate_master_password,
            invalid_message="The password must contain one uppercase, one lowercase, one symbol, and one digit and " +
                            "must be 8 or more characters"
        )

        return master_password_input(ui=ui)


class UINewMasterPasswordInput(IUIInputComponent):
    """
    # pypasscrypt.userinterface.UINewMasterPasswordInput
    -------------------------------------------------

    A class to handle new master password input for the Password Manager.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Example:
    -------
    >>> ui: UI = UI()
    >>> new_master_password_input: UINewMasterPasswordInput = UINewMasterPasswordInput()
    >>> new_master_password: str = ui.render(component=new_master_password_input)

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(
            self,
            *,
            new_password_message: str = "Enter the new master password:",
            confirm_password_message: str = "Confirm the new master password:"
    ) -> None:
        """
        # pypasscrypt.userinterface.UINewMasterPasswordInput.__init__
        --------------------------------------------------------

        Initialize the UINewMasterPassword object.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `new_password_message`: The new password message.
        - `confirm_password_message`: The confirm password message.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(new_password_message, str):
            raise TypeError("new_password_message must be a string.")
        
        if not isinstance(confirm_password_message, str):
            raise TypeError("confirm_password_message must be a string.")

        self.new_password_message: str = new_password_message
        self.confirm_password_message: str = confirm_password_message

    def __call__(self, *, ui: UI) -> str:
        """
        # pypasscrypt.userinterface.UINewMasterPasswordInput.__call__
        ----------------------------------------------------------

        Display the user interface.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ui`: The UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the ui is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The input provided by the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(ui, UI):  # checks if the ui is a UI object
            raise TypeError("ui must be a UI object.")

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
                ui.render(component=UINotificationDisplay(
                    message="Passwords do not match.", delay=1, style="error"))
                password = None
            else:
                password = new_master_password  # sets the password to the new master password

        return password  # returns the new master password


class UIFileInput(IUIInputComponent):
    """
    # pypasscrypt.userinterface.UIFileInput
    -------------------------------------

    A class to handle file input for the Password Manager.

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Example:
    -------
    >>> ui: UI = UI()
    >>> file_input: UIFileInput = UIFileInput(extension="bin", initial_dir="C:/users")
    >>> file_path: str = ui.render(component=file_input)

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
    """

    def __init__(self, *, extension: str, initial_dir: str) -> None:
        """
        # pypasscrypt.userinterface.UIFileInput.__init__
        ----------------------------------------------

        Initialize the UIFileInput object.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `extension`: The file extension.
        - `initial_dir`: The initial directory.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the parameters are invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(extension, str):
            raise TypeError("extension must be a string.")
        
        if not isinstance(initial_dir, str):
            raise TypeError("initial_dir must be a string.")

        self.extension: str = extension
        self.initial_dir: str = initial_dir

    def __call__(self, *, ui: UI) -> str:
        """
        # pypasscrypt.userinterface.UIFileInput.__call__
        ----------------------------------------------

        Display the user interface.
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Parameters:
        -----------
        - `ui`: The UI object.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Raises:
        -------
        - `TypeError`: If the ui is invalid.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Returns:
        --------
        The input provided by the user.

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Author: `Tejus Gupta` <`@tejus3131`, tejus3131@gmail.com>
        """

        if not isinstance(ui, UI):
            raise TypeError("ui must be a UI object.")

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
                ui.render(component=UINotificationDisplay(
                    message="Please select a file.", delay=1, style="error"))
                data = None
                continue

            extension = os.path.splitext(data)[1]
            if extension != f".{self.extension}":
                ui.render(component=UINotificationDisplay(
                    message=f"Please select a file with the extension '.{self.extension}'.", delay=1, style="error"))
                data = None
                continue

            if not isinstance(data, str) or not os.path.exists(data):
                ui.render(component=UINotificationDisplay(
                    message="File does not exist. Try again.", delay=1, style="error"))
                data = None
                continue

        return data
