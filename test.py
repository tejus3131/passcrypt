from rich.console import Console
from rich.table import Table

console = Console()
table = Table(title="Demo Table")

table.add_column("ID", justify="right", style="cyan", no_wrap=True)
table.add_column("Name", style="magenta")
table.add_column("Description", style="green")

table.add_row("1", "Foo", "A short description")
table.add_row("2", "Bar", "A longer description that will wrap")

console.print(table)