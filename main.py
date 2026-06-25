
import asyncio
import os
import sys
import argparse
import speedtest  # Menambahkan library speedtest

# Fungsi untuk memeriksa dependensi
def check_dependencies():
    missing_pip = []
    try: import dns.resolver
    except ImportError: missing_pip.append("dnspython")
    try: import rich
    except ImportError: missing_pip.append("rich")
    try: import speedtest
    except ImportError: missing_pip.append("speedtest-cli")
    
    if missing_pip:
        print(f"\n📦 Library belum terinstall: {', '.join(missing_pip)}")
        if input("➜ Install otomatis? [Y/n]: ").lower() != 'n':
            os.system(f"{sys.executable} -m pip install {' '.join(missing_pip)}")
            sys.exit(0)

check_dependencies()

from shared.ui import console, draw_main_menu, draw_exit
from shared.net import get_my_ip
from features import scanner, health, osint

async def run_speedtest():
    console.print("[bold cyan]🚀 Memulai uji kecepatan (Speedtest)...[/bold cyan]")
    st = speedtest.Speedtest()
    st.get_best_server()
    download = st.download() / 1_000_000
    upload = st.upload() / 1_000_000
    console.print(f"[green]✔ Download: {download:.2f} Mbps | Upload: {upload:.2f} Mbps[/green]")

async def main():
    parser = argparse.ArgumentParser(description="IP Tools - Python Edition")
    parser.add_argument("-s", "--scan", action="store_true", help="Langsung jalankan Local Scanner")
    parser.add_argument("-t", "--track", action="store_true", help="Langsung jalankan IP Tracker")
    parser.add_argument("-o", "--osint", metavar="TARGET", help="Langsung jalankan OSINT pada target")
    parser.add_argument("-hc", "--health", action="store_true", help="Langsung jalankan Health Check")
    parser.add_argument("-st", "--speedtest", action="store_true", help="Langsung jalankan Speedtest")
    args = parser.parse_args()

    my_ip = get_my_ip()
    prefix = ".".join(my_ip.split('.')[:3]) if my_ip else ""

    # Mode CLI langsung
    if args.scan:
        await scanner.run_local_scan_menu(prefix, my_ip)
        return
    elif args.track:
        await scanner.run_ip_tracker_menu(prefix, my_ip)
        return
    elif args.osint:
        osint_results = await osint.run_osint_recon_async(args.osint)
        osint.draw_osint_results(osint_results)
        return
    elif args.health:
        await health.run_health_menu()
        return
    elif args.speedtest:
        await run_speedtest()
        return

    # Mode Menu Interaktif
    while True:
        draw_main_menu()
        choice = input("\n ➜ Pilih menu [1/2/3/4/5/0]: ")
        if choice == '1': await scanner.run_local_scan_menu(prefix, my_ip)
        elif choice == '2': await scanner.run_ip_tracker_menu(prefix, my_ip)
        elif choice == '3': await health.run_health_menu()
        elif choice == '4': await osint.run_osint_menu()
        elif choice == '5': await run_speedtest()
        elif choice == '0':
            draw_exit()
            break

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
