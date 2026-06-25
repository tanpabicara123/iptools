
import asyncio
import os
import re
import time
import urllib.request
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich import box

from shared.ui import console, get_latency_color
from shared.config import TARGETS_FILE

# ================= Logika Health Check & Speedtest =================

def load_targets():
    if not os.path.exists(TARGETS_FILE):
        default_targets = ["8.8.8.8", "1.1.1.1", "facebook.com", "google.com"]
        with open(TARGETS_FILE, "w") as f:
            f.write("\n".join(default_targets))
    with open(TARGETS_FILE, "r") as f:
        targets = [line.strip() for line in f.read().splitlines() if line.strip()]
    return targets

async def async_wan_ping(target):
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "4", "-W", "1", target,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode('utf-8', errors='ignore')

        packet_loss = 100
        loss_match = re.search(r'(\d+)%\s*packet\s*loss', output)
        if loss_match:
            packet_loss = int(loss_match.group(1))

        avg_ping = 0.0
        if packet_loss < 100:
            ping_match = re.search(r'=\s*[\d\.]+/(?P<avg>[\d\.]+)/', output)
            if ping_match:
                avg_ping = float(ping_match.group('avg'))

        return {"target": target, "loss": packet_loss, "ping": avg_ping}
    except Exception:
        return {"target": target, "loss": 100, "ping": 0.0}

async def run_health_check_async(targets):
    results = []
    with Progress(
        SpinnerColumn(spinner_name="line", style="magenta"),
        TextColumn("[bold magenta]Menguji kestabilan koneksi global (Mohon tunggu 4 detik)...[/bold magenta]"),
        console=console
    ) as progress:
        progress.add_task("wait", total=None)
        tasks = [async_wan_ping(t) for t in targets]
        results = await asyncio.gather(*tasks)
    return results

_CF_DL_URL = "https://speed.cloudflare.com/__down?bytes=10000000"
_CF_UL_URL = "https://speed.cloudflare.com/__up"
_LS_DL_URL = "https://librespeed.snt.utwente.nl/backend/garbage.php?ckSize=10"
_LS_UL_URL = "https://librespeed.snt.utwente.nl/backend/empty.php"

async def _test_download(url, label):
    """Download 10MB dari provider, return kecepatan dalam Mbps."""
    try:
        def do_download():
            req = urllib.request.Request(url, headers={
                'User-Agent':    'Mozilla/5.0 (Linux; Android 10)',
                'Cache-Control': 'no-cache'
            })
            start = time.time()
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            elapsed = time.time() - start
            size = len(data)
            if elapsed > 0 and size > 0:
                return (size * 8) / (elapsed * 1_000_000)
            return 0.0

        mbps = await asyncio.to_thread(do_download)
        return {"provider": label, "mbps": round(mbps, 2), "error": None}
    except Exception as e:
        return {"provider": label, "mbps": 0.0, "error": str(e)[:60]}

async def _test_upload(url, label):
    """Upload 10MB ke provider, return kecepatan dalam Mbps."""
    try:
        def do_upload():
            chunk = os.urandom(1_000_000)
            data  = chunk * 10
            req = urllib.request.Request(url, data=data, headers={
                'User-Agent':     'Mozilla/5.0 (Linux; Android 10)',
                'Content-Type':   'application/octet-stream',
                'Content-Length': str(len(data)),
                'Cache-Control':  'no-cache'
            })
            start = time.time()
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp.read()
            elapsed = time.time() - start
            if elapsed > 0:
                return (len(data) * 8) / (elapsed * 1_000_000)
            return 0.0

        mbps = await asyncio.to_thread(do_upload)
        return {"provider": label, "mbps": round(mbps, 2), "error": None}
    except Exception as e:
        return {"provider": label, "mbps": 0.0, "error": str(e)[:60]}

async def run_speedtest_async():
    console.print(" [bold cyan][ ⬇ ][/bold cyan] [cyan]Menguji Download (Cloudflare + LibreSpeed)...[/cyan]")
    dl_cf, dl_ls = await asyncio.gather(
        _test_download(_CF_DL_URL, "Cloudflare"),
        _test_download(_LS_DL_URL, "LibreSpeed"),
    )
    console.print(" [bold green][ ✔ ][/bold green] [cyan]Download Test (Selesai)[/cyan]")

    console.print(" [bold yellow][ ⬆ ][/bold yellow] [yellow]Menguji Upload (Cloudflare + LibreSpeed)...[/yellow]")
    ul_cf, ul_ls = await asyncio.gather(
        _test_upload(_CF_UL_URL, "Cloudflare"),
        _test_upload(_LS_UL_URL, "LibreSpeed"),
    )
    console.print(" [bold green][ ✔ ][/bold green] [yellow]Upload Test (Selesai)[/yellow]")

    console.print(" [bold magenta][ ◎ ][/bold magenta] [magenta]Mengukur Ping...[/magenta]")
    ping_result = await async_wan_ping("speed.cloudflare.com")
    ping_ms = ping_result.get("ping", 0.0)
    console.print(" [bold green][ ✔ ][/bold green] [magenta]Ping (Selesai)[/magenta]")

    dl_valid = [r for r in [dl_cf, dl_ls] if not r["error"] and r["mbps"] > 0]
    ul_valid = [r for r in [ul_cf, ul_ls] if not r["error"] and r["mbps"] > 0]

    avg_dl = round(sum(r["mbps"] for r in dl_valid) / len(dl_valid), 2) if dl_valid else 0.0
    avg_ul = round(sum(r["mbps"] for r in ul_valid) / len(ul_valid), 2) if ul_valid else 0.0

    return {
        "download_results": [dl_cf, dl_ls],
        "upload_results":   [ul_cf, ul_ls],
        "avg_download":     avg_dl,
        "avg_upload":       avg_ul,
        "ping":             ping_ms,
    }

# ================= UI Health Check =================

def draw_health_submenu(targets):
    console.clear()
    target_list = "\n".join([f"  [cyan]➜[/cyan] {t}" for t in targets])
    if not targets:
        target_list = "  [dim](Tidak ada target server, silakan edit file!)[/dim]"

    menu_text = (
        f"[bold yellow]Target Server Saat Ini ({len(targets)} Server):[/bold yellow]\n"
        f"{target_list}\n\n"
        " [bold green]1.[/bold green] Mulai Ping & Packet Loss Test\n"
        " [bold cyan]2.[/bold cyan] Mulai Speedtest (Bandwidth Download & Upload)\n"
        " [bold yellow]3.[/bold yellow] Edit Target Server (via Nano)\n"
        " [bold red]0.[/bold red] Kembali ke Menu Utama"
    )
    panel = Panel(menu_text, title="[bold magenta]🌐 Internet Health Check[/bold magenta]", expand=False, box=box.ROUNDED, border_style="magenta")
    console.print(panel)

def draw_health_results(results):
    table = Table(title="[bold magenta]Laporan Kualitas Jaringan Global[/bold magenta]", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Target Server", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Packet Loss", justify="center")
    table.add_column("Rata-rata Ping", justify="center")

    total_loss, total_ping, valid_pings = 0, 0, 0

    for res in results:
        target = res['target']
        loss   = res['loss']
        ping   = res['ping']

        loss_str = f"[green]{loss}%[/green]" if loss == 0 else (f"[yellow]{loss}%[/yellow]" if loss < 100 else f"[red]{loss}%[/red]")

        if loss == 100:
            status_str = "[bold red]DOWN / RTO[/bold red]"
            ping_str   = "[dim]-[/dim]"
        else:
            status_str = "[bold green]UP[/bold green]"
            color      = get_latency_color(ping)
            ping_str   = f"[{color}]{ping:.2f} ms[/{color}]"
            total_ping += ping
            valid_pings += 1

        total_loss += loss
        table.add_row(target, status_str, loss_str, ping_str)

    console.print("\n")
    console.print(Align.center(table))

    avg_total_loss = (total_loss / len(results)) if results else 100
    avg_total_ping = (total_ping / valid_pings) if valid_pings > 0 else 0

    if avg_total_loss == 100:
        health, desc, border = "[bold red]TERPUTUS (Offline)[/bold red]", "Koneksi ISP mati total atau tidak ada akses internet.", "red"
    elif avg_total_loss == 0 and avg_total_ping > 120:
        health, desc, border = "[bold yellow]TIDAK STABIL (Ping Tinggi)[/bold yellow]", "Tidak ada packet loss, tapi rata-rata ping terlalu lambat (>120ms).", "yellow"
    elif avg_total_loss > 25 and avg_total_ping < 50:
        health, desc, border = "[bold yellow]TIDAK STABIL (Loss Parah)[/bold yellow]", "Ping cepat, tapi terlalu banyak paket yang hilang (>25%).", "yellow"
    elif avg_total_loss > 25:
        health, desc, border = "[bold yellow]TIDAK STABIL (Gangguan)[/bold yellow]", "Koneksi buruk dengan packet loss sangat tinggi.", "yellow"
    elif avg_total_loss > 15 and avg_total_ping < 50:
        health, desc, border = "[bold cyan]BAIK (Normal)[/bold cyan]", "Ada packet loss, tapi koneksi tertolong karena ping sangat cepat (<50ms).", "cyan"
    elif avg_total_loss > 15:
        health, desc, border = "[bold yellow]TIDAK STABIL (Loss Sedang)[/bold yellow]", "Packet loss di atas 15% dengan ping yang lambat. Koneksi tidak stabil.", "yellow"
    elif avg_total_loss == 0 and avg_total_ping < 50:
        health, desc, border = "[bold green]SANGAT BAIK[/bold green]", "Koneksi sempurna. 0% Loss dan ping sangat cepat.", "green"
    else:
        health, desc, border = "[bold cyan]BAIK (Normal)[/bold cyan]", "Koneksi internet berjalan normal dan stabil.", "cyan"

    conclusion = Panel(
        f"Kualitas Internet : {health}\nCatatan           : [dim]{desc}[/dim]",
        title="[bold]Kesimpulan Akhir[/bold]",
        box=box.ROUNDED,
        border_style=border,
        expand=False
    )
    console.print("\n")
    console.print(Align.center(conclusion))

def draw_speedtest_results(results):
    dl_results = results.get("download_results", [])
    ul_results = results.get("upload_results",   [])
    avg_dl     = results.get("avg_download",     0.0)
    avg_ul     = results.get("avg_upload",       0.0)
    ping_ms    = results.get("ping",             0.0)

    table = Table(
        title="[bold cyan]Hasil Uji Kecepatan Bandwidth[/bold cyan]",
        box=box.ROUNDED, header_style="bold magenta"
    )
    table.add_column("Provider",  style="cyan",   justify="left",  min_width=12)
    table.add_column("Download",  justify="right", min_width=12)
    table.add_column("Upload",    justify="right", min_width=12)

    for i in range(max(len(dl_results), len(ul_results))):
        dl = dl_results[i] if i < len(dl_results) else {}
        ul = ul_results[i] if i < len(ul_results) else {}

        provider = dl.get("provider") or ul.get("provider") or "-"

        if dl.get("error"):
            dl_str = "[red]✖ Gagal[/red]"
        else:
            dl_mbps = dl.get("mbps", 0.0)
            dl_col  = "green" if dl_mbps >= 10 else ("yellow" if dl_mbps >= 5 else "red")
            dl_str  = f"[{dl_col}]{dl_mbps:.2f} Mbps[/{dl_col}]"

        if ul.get("error"):
            ul_str = "[red]✖ Gagal[/red]"
        else:
            ul_mbps = ul.get("mbps", 0.0)
            ul_col  = "green" if ul_mbps >= 5 else ("yellow" if ul_mbps >= 2 else "red")
            ul_str  = f"[{ul_col}]{ul_mbps:.2f} Mbps[/{ul_col}]"

        table.add_row(provider, dl_str, ul_str)

    table.add_section()
    avg_dl_col = "green" if avg_dl >= 10 else ("yellow" if avg_dl >= 5 else "red")
    avg_ul_col = "green" if avg_ul >= 5  else ("yellow" if avg_ul >= 2 else "red")
    table.add_row(
        "[bold white]Rata-rata[/bold white]",
        f"[bold {avg_dl_col}]{avg_dl:.2f} Mbps[/bold {avg_dl_col}]",
        f"[bold {avg_ul_col}]{avg_ul:.2f} Mbps[/bold {avg_ul_col}]"
    )

    console.print("\n")
    console.print(Align.center(table))

    ping_color = "green" if ping_ms <= 50 else ("yellow" if ping_ms <= 100 else "red")
    ping_panel = Panel(
        f" [bold]Ping ke Cloudflare:[/bold] [{ping_color}]{ping_ms:.2f} ms[/{ping_color}]",
        expand=False,
        border_style=ping_color
    )
    console.print(Align.center(ping_panel))

# ================= Controller Menu =================

async def run_health_menu():
    while True:
        targets = load_targets()
        draw_health_submenu(targets)

        sub_choice = input("\n ➜ Pilih opsi [1/2/3/0]: ")

        if sub_choice == '1':
            console.print("\n")
            if not targets:
                console.print("[bold red]Target kosong! Silakan edit file terlebih dahulu.[/bold red]")
            else:
                health_results = await run_health_check_async(targets)
                draw_health_results(health_results)

            console.print("\n[dim]----------------------------------------[/dim]")
            input(" Tekan [ENTER] untuk kembali...")

        elif sub_choice == '2':
            console.print("\n")
            try:
                speedtest_results = await run_speedtest_async()
                draw_speedtest_results(speedtest_results)
            except ImportError:
                console.print("[bold red]Error: Library 'speedtest-cli' belum terinstall.[/bold red]")
            except Exception as e:
                console.print(f"\n[bold red]Ups, terjadi kegagalan saat Speedtest: {e}[/bold red]")
                console.print("[dim]Pastikan koneksi internet aktif.[/dim]")

            console.print("\n[dim]----------------------------------------[/dim]")
            input(" Tekan [ENTER] untuk kembali...")

        elif sub_choice == '3':
            os.system(f"nano {TARGETS_FILE}")

        elif sub_choice == '0':
            break


