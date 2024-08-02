from time import sleep
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.live import Live
from rich.layout import Layout

def animate_message(message, border_style="blue", title="Message", wait_time=1):
    console = Console()
    max_length = len(message)
    
    layout = Layout()
    layout.split(
        Layout(name="main", ratio=1)
    )

    with Live(layout, refresh_per_second=60, console=console, screen=True) as live:
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

# Example usage
animate_message("Hello, World!")
