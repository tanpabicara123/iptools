
import socket
import struct
import sys

def test_ssdp_socket():
    print("[*] Menguji socket SSDP (UPnP)...")
    try:
        # 1. Membuat socket UDP standard
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(3.0)
        print("  [✔] Berhasil membuat socket UDP.")
        
        # 2. Mengatur opsi socket agar bisa menggunakan multicast ttl (Time To Live)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            print("  [✔] Berhasil mengatur IP_MULTICAST_TTL.")
        except Exception as e:
            print(f"  [❌] Gagal setsockopt IP_MULTICAST_TTL: {e}")
            return False

        # 3. Mencoba mengirim paket SSDP M-SEARCH ke IP Multicast SSDP
        # Alamat multicast UPnP/SSDP: 239.255.255.250 port 1900
        ssdp_target = ("239.255.255.250", 1900)
        ssdp_query = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode('utf-8')

        try:
            sock.sendto(ssdp_query, ssdp_target)
            print("  [✔] Berhasil mengirim paket multicast SSDP ke 239.255.255.250:1900.")
        except PermissionError as pe:
            print(f"  [❌] Permission Denied saat mengirim paket: {pe}")
            print("      -> Android 15 memblokir transmisi multicast lokal di level userland.")
            return False
        except Exception as e:
            print(f"  [❌] Gagal mengirim paket SSDP: {e}")
            return False

        # 4. Mencoba mendengarkan respons (jika ada perangkat yang menjawab)
        print("  [*] Menunggu respons dari perangkat lokal (3 detik)...")
        try:
            data, addr = sock.recvfrom(1024)
            print(f"  [🎉] SUKSES! Menerima respons dari {addr[0]}:\n{data.decode('utf-8', errors='ignore')[:150]}...")
            return True
        except socket.timeout:
            print("  [✔] Socket aman (Tidak crash/Error), hanya tidak ada respons (Timeout biasa).")
            return True
        except Exception as e:
            print(f"  [❌] Gagal membaca respons: {e}")
            return False
        finally:
            sock.close()

    except Exception as e:
        print(f"  [❌] Error tidak terduga pada SSDP: {e}")
        return False

def test_mdns_socket():
    print("\n[*] Menguji socket mDNS...")
    try:
        # 1. Membuat socket UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(3.0)
        print("  [✔] Berhasil membuat socket UDP.")

        # 2. Mencoba bind ke port ephemeral (bebas/acak)
        try:
            sock.bind(("", 0))
            print("  [✔] Berhasil melakukan bind ke local port.")
        except Exception as e:
            print(f"  [❌] Gagal melakukan bind: {e}")
            return False

        # 3. Mencoba mengirimkan query mDNS standar ke 224.0.0.251 port 5353
        # Query mDNS minimalis untuk mencari layanan web (_http._tcp.local)
        mdns_target = ("224.0.0.251", 5353)
        mdns_query = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05_http\x04_tcp\x05local\x00\x00\x0c\x00\x01'

        try:
            sock.sendto(mdns_query, mdns_target)
            print("  [✔] Berhasil mengirim paket multicast mDNS ke 224.0.0.251:5353.")
        except PermissionError as pe:
            print(f"  [❌] Permission Denied saat mengirim mDNS: {pe}")
            return False
        except Exception as e:
            print(f"  [❌] Gagal mengirim paket mDNS: {e}")
            return False
        finally:
            sock.close()
            
        return True
    except Exception as e:
        print(f"  [❌] Error tidak terduga pada mDNS: {e}")
        return False

if __name__ == "__main__":
    print("=== MULTICAST FEASIBILITY CHECK (ANDROID 15 / TERMUX) ===\n")
    ssdp_ok = test_ssdp_socket()
    mdns_ok = test_mdns_socket()
    
    print("\n================== KESIMPULAN ==================")
    if ssdp_ok and mdns_ok:
        print("[STATUS] AMAN! Sistem lu mengizinkan socket multicast tanpa kendala perizinan.")
        print("Kita bisa lanjut ke tahap implementasi penuh.")
    else:
        print("[STATUS] TERBATAS/DIBlOKIR! Terdeteksi adanya batasan 'Permission denied' atau error socket.")
        print("Silakan periksa izin Termux atau gunakan metode alternatif.")
    print("=================================================")
