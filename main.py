import asyncio
import os
import sys
import argparse
from shared.ui import console, draw_main_menu, draw_exit
from shared.net import get_my_ip
from features import scanner, health, osint

async def main():
    parser = argparse.ArgumentParser(description="IP Tools - Python Edition")
    parser.add_argument("-s", "--scan", action="store_true")
    parser.add_argument("-t", "--track", action="store_true")
    parser.add_argument("-o", "--osint", metavar="TARGET")
    parser.add_argument("-hc", "--health", action="store_true")
    parser.add_argument("-st", "--speedtest", action="store_true")
    args = parser.parse_args()

    my_ip = get_my_ip()
    prefix = ".".join(my_ip.split('.')[:3]) if my_ip else ""

    if args.scan:
        await scanner.run_local_scan_menu(prefix, my_ip)
    elif args.track:
        await scanner.run_ip_tracker_menu(prefix, my_ip)
    elif args.osint:
        osint_results = await osint.run_osint_recon_async(args.osint)
        osint.draw_osint_results(osint_results)
    elif args.health:
        await health.run_health_menu()
    elif args.speedtest:
        await health.run_speedtest_async()  # FIX: nama benar + await
    else:
        while True:
            draw_main_menu()
            choice = input("\n ➜ Pilih menu [1/2/3/4/0]: ")
            if choice == '1': await scanner.run_local_scan_menu(prefix, my_ip)
            elif choice == '2': await scanner.run_ip_tracker_menu(prefix, my_ip)
            elif choice == '3': await health.run_health_menu()
            elif choice == '4': await osint.run_osint_menu()
            elif choice == '0':
                draw_exit()
                break

if __name__ == "__main__":
    asyncio.run(main())
