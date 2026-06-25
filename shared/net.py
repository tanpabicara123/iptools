
import socket

def get_my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def is_ip_address(target):
    """Return True jika target adalah IPv4 address yang valid."""
    try:
        socket.inet_pton(socket.AF_INET, target)
        return True
    except socket.error:
        return False


