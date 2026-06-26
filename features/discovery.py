
import asyncio
import socket
import re
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich import box

from shared.ui import console

def discover_ssdp_worker():
    """Worker sinkronus untuk mengendus broadcast paket SSDP (UPnP)."""
    devices = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(2.5)
    
    # Atur TTL multicast ke 2 agar bisa menjangkau hop jaringan lokal terdekat
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    
    ssdp_query = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode('utf-8')
    
    try:
        sock.sendto(ssdp_query, ("239.255.255.250", 1900))
        while True:
            data, addr = sock.recvfrom(2048)
            ip = addr[0]
            decoded = data.decode('utf-8', errors='ignore')
            
            # Ekstraksi header Server dan Search Target (ST)
            server_match = re.search(r'SERVER:\s*(.*)', decoded, re.IGNORECASE)
            st_match = re.search(r'ST:\s*(.*)', decoded, re.IGNORECASE)
            
            server_info = server_match.group(1).strip() if server_match else "UPnP Protocol Device"
            st_info = st_match.group(1).strip() if st_match else ""
            
            # Tebak tipe device berdasarkan raw fingerprint signature
            device_type = "Smart Device / IoT"
            raw_lower = decoded.lower()
            if "roku" in raw_lower:
                device_type = "📺 Roku Stream TV"
            elif "chromecast" in raw_lower or "google" in raw_lower:
                device_type = "📱 Google Cast / Android"
            elif "linux" in raw_lower:
                device_type = "🌐 Linux System / Router"
            elif "windows" in raw_lower:
                device_type = "💻 Windows Server/PC"
                
            devices[ip] = {
                "name": device_type,
                "protocol": "SSDP (UPnP)",
                "detail": f"{server_info[:35]}... ({st_info[:15]})" if len(server_info) > 35 else f"{server_info} ({st_info[:15]})"
            }
    except socket.timeout:
        pass
    finally:
        sock.close()
    return devices

def discover_mdns_worker():
    """Worker sinkronus untuk menyisir kueri mDNS perangkat pintar lokal."""
    devices = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(2.5)
    sock.bind(("", 0))
    
    # Target kueri mDNS: DNS PTR kustom untuk tipe layanan populer Android & Media
    queries = [
        # Discovery semua tipe service lokal
        b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\t_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01',
        # Google Cast / Android TV / HP Android Mirroring
        b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0b_googlecast\x04_tcp\x05local\x00\x00\x0c\x00\x01',
        # Spotify Connect
        b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x10_spotify-connect\x04_tcp\x05local\x00\x00\x0c\x00\x01',
        # Wireless ADB Debugging (Android Dev Flag)
        b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x11_adb-tls-connect\x04_tcp\x05local\x00\x00\x0c\x00\x01'
    ]
    
    for q in queries:
        try:
            sock.sendto(q, ("224.0.0.251", 5353))
        except Exception:
            pass
            
    try:
        while True:
            data, addr = sock.recvfrom(2048)
            ip = addr[0]
            raw_str = data.lower()
            
            # Parsing string mentah dari payload DNS untuk mencari nama perangkat
            strings = re.findall(b'[a-zA-Z0-9\-\s_]{4,}', data)
            readable_chunks = [s.decode('utf-8', errors='ignore') for s in strings if not s.startswith(b'_')]
            
            name_hint = "📱 Perangkat Android / Apple"
            detail_hint = "Merespons via Multicast DNS"
            
            if b'google' in raw_str or b'cast' in raw_str:
                name_hint = "📺 Android TV / Google Cast"
                detail_hint = "Layanan casting aktif"
            elif b'spotify' in raw_str:
                name_hint = "🎵 Spotify Endpoint"
                detail_hint = "Sedang memutar media player"
            elif b'adb' in raw_str:
                name_hint = "⚙️ Android Developer (ADB)"
                detail_hint = "Wireless Debugging Aktif! (Port Terbuka)"
                
            valid_names = [n for n in readable_chunks if n.lower() not in ('local', 'tcp', 'udp', 'http', 'services', 'dns-sd')]
            if valid_names:
                detail_hint = f"Nama: {valid_names[0]}"
                
            devices[ip] = {
                "name": name_hint,
                "protocol": "mDNS",
                "detail": detail_hint
            }
    except socket.timeout:
        pass
    finally:
        sock.close()
    return devices

async def run_discovery_async():
    """Menyatukan hasil pemindaian asinkronus SSDP & mDNS."""
    with Progress(
        SpinnerColumn(spinner_name="moon", style="bold cyan"),
        TextColumn("[bold cyan]Menyiarkan kueri Zero-Conf & mengendus respon lokal...[/bold cyan]"),
        console=console,
        transient=True
    ) as progress:
        progress.add_task("discover", total=None)
        
        # Eksekusi kedua pencarian secara independen di thread pool paralel
        ssdp_task = asyncio.to_thread(discover_ssdp_worker)
        mdns_task = asyncio.to_thread(discover_mdns_worker)
        
        ssdp_results, mdns_results = await asyncio.gather(ssdp_task, mdns_task)
        
    # Gabungkan data berdasarkan IP address unik
    combined = {}
    combined.update(ssdp_results)
    for ip, info in mdns_results.items():
        if ip in combined:
            combined[ip]["detail"] += f" | {info['detail']}"
            if "Protocol" in combined[ip]["name"] or "Smart" in combined[ip]["name"]:
                combined[ip]["name"] = info["name"]
            combined[ip]["protocol"] += " + mDNS"
        else:
            combined[ip] = info
            
    return combined

def draw_discovery_results(results, my_ip):
    """Menampilkan hasil penemuan ke layar Termux dengan rapi."""
    console.print(f"\n[bold green]📍 IP Lokal Anda:[/bold green] {my_ip}")
    console.print(f"[bold cyan]📡 Layanan Zero-Conf Terendus:[/bold cyan] {len(results)} Perangkat\n")
    
    table = Table(title="[bold magenta]Zero-Conf Network Service Discovery[/bold magenta]", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("IP Address", justify="center", style="cyan", min_width=15)
    table.add_column("Klasifikasi Perangkat", justify="left", style="white", min_width=25)
    table.add_column("Protokol", justify="center", style="yellow", min_width=12)
    table.add_column("Detail Penemuan / Atribut Terbuka", justify="left", style="green", min_width=35)
    
    if not results:
        table.add_row("-", "Tidak ada perangkat zero-conf merespon", "-", "Pastikan Anda terhubung ke Wi-Fi lokal")
    else:
        # Sortir hasil urut berdasarkan segmen IP terakhir
        sorted_ips = sorted(results.keys(), key=lambda x: int(x.split('.')[3]) if len(x.split('.')) == 4 else 0)
        for ip in sorted_ips:
            dev = results[ip]
            table.add_row(ip, dev["name"], dev["protocol"], dev["detail"])
            
    console.print(Align.center(table))

async def run_discovery_menu(my_ip):
    """Controller utama untuk dipanggil dari main loop."""
    console.print("\n")
    results = await run_discovery_async()
    draw_discovery_results(results, my_ip)
    
    console.print("\n[dim]----------------------------------------[/dim]")
    input(" Tekan [ENTER] untuk kembali ke menu...")

