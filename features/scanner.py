
import asyncio
import os
import re
import socket
from datetime import datetime
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich import box

from shared.ui import console, get_latency_color
from shared.config import LOG_FILE, TIME_FILE

# ================= Logika Local Scanner =================

def parse_ttl(output):
    """Extract TTL value dari output ping dan return device hint."""
    try:
        match = re.search(r'ttl=(\d+)', output, re.IGNORECASE)
        if match:
            ttl_received = int(match.group(1))

            # Normalisasi ke initial TTL terdekat dari atas
            standard_ttls = [64, 128, 255]
            initial_ttl = min(
                (s for s in standard_ttls if s >= ttl_received),
                default=255
            )

            if initial_ttl == 255:
                return ttl_received, "🔀 Kemungkinan Router/Switch"
            elif initial_ttl == 128:
                return ttl_received, "💻 Kemungkinan Windows"
            else:
                return ttl_received, "📱 Kemungkinan Android/Linux"
    except Exception:
        pass
    return None, "❓ Unknown"

async def get_hostname(ip):
    """Resolve hostname via reverse DNS. Return '-' jika gagal."""
    try:
        result = await asyncio.to_thread(socket.gethostbyaddr, ip)
        hostname = result[0]
        return hostname[:30] + ".." if len(hostname) > 30 else hostname
    except Exception:
        return "-"

async def async_ping_ip(ip):
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", "1", ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await proc.communicate()
        if proc.returncode == 0:
            output = stdout.decode()
            start = output.find("time=")
            if start != -1:
                end = output.find(" ms", start)
                time_val = float(output[start+5:end])
                ttl, hint = parse_ttl(output)
                return (ip, time_val, ttl, hint)
        return None
    except Exception:
        return None

async def safe_ping(ip, sem, progress, task_id):
    async with sem:
        result = await async_ping_ip(ip)
        progress.advance(task_id)
        return result

async def run_scan_async(prefix):
    found = []
    ips_to_scan = [f"{prefix}.{i}" for i in range(1, 255)]
    sem = asyncio.Semaphore(25)

    with Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[bold yellow]Scanning...[/bold yellow]"),
        BarColumn(bar_width=40, style="cyan", complete_style="green"),
        TextColumn("[cyan]({task.completed}/{task.total})[/cyan]"),
        console=console
    ) as progress:
        task_id = progress.add_task("ping", total=len(ips_to_scan))
        tasks = [safe_ping(ip, sem, progress, task_id) for ip in ips_to_scan]
        results = await asyncio.gather(*tasks)
        for result in results:
            if result is not None:
                found.append(result)

    found.sort(key=lambda x: int(x[0].split('.')[3]))
    return found

# ================= UI Scanner =================

def draw_scan_results(results, my_ip):
    console.print(f"\n[bold green]📍 IP Lokal Anda:[/bold green] {my_ip}")
    console.print(f"[bold cyan]📊 Total Perangkat Terhubung:[/bold cyan] {len(results)}\n")

    table = Table(title="[bold magenta]Hasil Pemindaian Jaringan[/bold magenta]", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Status",     justify="center", style="bold green", min_width=6)
    table.add_column("IP Address", justify="center", style="cyan",       min_width=15)
    table.add_column("Latency",    justify="center",                     min_width=10)

    for row in results:
        ip   = row[0]
        lat  = row[1]
        ttl  = row[2]
        hint = row[3]

        color   = get_latency_color(lat)
        ttl_str = str(ttl) if ttl is not None else "-"

        table.add_row(
            "● UP",
            ip,
            f"[{color}]{lat:.2f} ms[/{color}]"
        )
        table.add_row(
            "",
            f"[dim]Hint: {hint} ({ttl_str})[/dim]",
            ""
        )

    console.print(Align.center(table))

def draw_tracker_results(current_ips, new_ips, gone_ips, last_time, my_ip):
    console.print(f"\n[bold green]📍 IP Lokal Anda:[/bold green] {my_ip}")
    console.print(f"[bold cyan]📈 Status Jaringan:[/bold cyan] {len(current_ips)} Perangkat terhubung.")

    sorted_current = sorted(list(current_ips), key=lambda x: int(x.split('.')[3]))
    current_text = "\n".join([f"[cyan]●[/cyan] {ip}" for ip in sorted_current]) if sorted_current else "[dim]Tidak ada perangkat[/dim]"
    p_current = Panel(current_text, title="[bold cyan]Daftar Perangkat Saat Ini[/bold cyan]", expand=False, box=box.ROUNDED, border_style="cyan")

    new_text = "\n".join([f"[green]●[/green] {ip}" for ip in new_ips]) if new_ips else "[dim]Tidak ada perangkat baru[/dim]"
    p_new = Panel(new_text, title="[bold green]Baru / Masuk[/bold green]", expand=False, box=box.ROUNDED, border_style="green")

    gone_text = "\n".join([f"[red]●[/red] {ip}" for ip in gone_ips]) if gone_ips else "[dim]Tidak ada perangkat keluar[/dim]"
    p_gone = Panel(gone_text, title="[bold red]Terputus / Keluar[/bold red]", expand=False, box=box.ROUNDED, border_style="red")

    console.print("\n")
    console.print(p_current)
    console.print(p_new)
    console.print(p_gone)

    console.print(f"\n[yellow]🕒 Log Terakhir:[/yellow] {last_time}")
    console.print("\n[dim]----------------------------------------[/dim]")

# ================= Controller Menu =================

async def run_local_scan_menu(prefix, my_ip):
    console.print("\n")
    results = await run_scan_async(prefix)
    draw_scan_results(results, my_ip)

    ip_list = [r[0] for r in results]
    with open(LOG_FILE, "w") as f:
        f.write("\n".join(ip_list))
    with open(TIME_FILE, "w") as f:
        f.write(datetime.now().strftime("%d %b %Y, %H:%M WIB"))

    console.print("\n[dim]----------------------------------------[/dim]")
    input(" Tekan [ENTER] untuk kembali ke menu...")

async def run_ip_tracker_menu(prefix, my_ip):
    console.print("\n")
    old_ips = set()
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            old_ips = set(f.read().splitlines())

    results     = await run_scan_async(prefix)
    current_ips = {r[0] for r in results}

    last_time = "Belum ada log"
    if os.path.exists(TIME_FILE):
        with open(TIME_FILE, "r") as f:
            last_time = f.read()

    new_ips  = current_ips - old_ips
    gone_ips = old_ips - current_ips

    draw_tracker_results(current_ips, new_ips, gone_ips, last_time, my_ip)

    with open(LOG_FILE, "w") as f:
        f.write("\n".join(current_ips))
    with open(TIME_FILE, "w") as f:
        f.write(datetime.now().strftime("%d %b %Y, %H:%M WIB"))

    input(" Tekan [ENTER] untuk kembali ke menu...")



