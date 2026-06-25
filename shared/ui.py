
from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()

def get_latency_color(val):
    if val <= 90: return "green"
    elif val <= 170: return "yellow"
    else: return "red"

def draw_main_menu():
    console.clear()
    menu_text = (
        " [bold green]1.[/bold green] Local Scanner\n"
        " [bold yellow]2.[/bold yellow] IP Tracker\n"
        " [bold magenta]3.[/bold magenta] Internet Health Check\n"
        " [bold blue]4.[/bold blue] OSINT Target Analyzer (DNS & Traceroute)\n"
        " [bold red]0.[/bold red] Keluar"
    )
    menu_panel = Panel(
        menu_text,
        title="[bold cyan]IP TOOLS - PYTHON EDITION[/bold cyan]",
        subtitle="[dim]Pilih salah satu opsi[/dim]",
        expand=False,
        box=box.ROUNDED,
        border_style="cyan"
    )
    console.print(menu_panel)

def draw_exit():
    console.print("\n[bold green]Terima kasih telah menggunakan tools ini! 🚀[/bold green]\n")

