from pip._vendor.rich.console import Console
from pip._vendor.rich import print
from pip._vendor.rich.table import Table
import os
import stat
import pwd
import time


def _sizeof_fmt(num, suffix="B", is_dir=False):
    if num == 0:
        return "-"
    for unit in ["","K","M","G","T","P","E","Z"]:
        if abs(num) < 1024.0:
            return f"{int(num)}{unit}"
        num /= 1024.0
    return f"{int(num)}"

def _colorize_permissions(permissions):
    colored_permissions = ""
    for char in permissions:
        if char == "r":
            colored_permissions += "[yellow]r[/yellow]"
        elif char == "w":
            colored_permissions += "[red]w[/red]"
        elif char == "x":
            colored_permissions += "[green]x[/green]"
        elif char == "d":
            colored_permissions += "[blue]d[/blue]"
        else:
            colored_permissions += char
    return colored_permissions

def ls(data):
    console = Console()
    # items = sorted(os.scandir(path), key=lambda item: item.name)


    table = Table(show_header=True, header_style="bold white", box=False, padding=(0,2,0,0))
    table.add_column("Permissions", justify="left")
    table.add_column("Size", justify="right")
    table.add_column("Owner", justify="left")
    table.add_column("Date", justify="left")
    table.add_column("Name", justify="left")

    for item in data:
        file_info = item['stat']
        file_permissions = _colorize_permissions(stat.filemode(file_info['st_mode']))
        file_size = _sizeof_fmt(file_info['st_size'], is_dir=item['is_dir'])
        file_owner = pwd.getpwuid(file_info['st_uid']).pw_name
        file_date = time.strftime("%d %b %H:%M", time.gmtime(file_info['st_mtime']))
        file_color = "blue" if item['is_dir'] else "white"

        table.add_row(
            f"[bold]{file_permissions}[/bold]",
            f"[green]{file_size}[/green]",
            f"[bold yellow]{file_owner}[/bold yellow]",
            f"[blue]{file_date}[/blue]",
            f"[{file_color}]{item['name']}[/{file_color}]",
        )

    console.print(table)

def do_ls(self, line):
    if not line:
        path = pretty(self.server.send_command("pwd"))
        ls = pretty(self.server.send_command("ls -la"))
    else:
        if line[0] == "-":
            logging.error("um dont do that. placeholder text.")
            return
        ls = pretty(self.server.send_command(f"ls -la {line}"))
        if "no such file or directory" in ls.lower():
            logging.error("No such file or directory")
            return
        if line == "/":
            path = "root"
        else:
            path = pretty(self.server.send_command(f"realpath {line}"))
    ls = "\n".join(ls.split("\n")[1:])
    sys.stdout.write(f"{path}\n{'=' * (len(path))}\n{ls}\n")