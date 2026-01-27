
import socket
import sys

def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex(('127.0.0.1', port))
    if result == 0:
        print(f"[OK] Port {port} is OPEN")
        return True
    else:
        print(f"[ERROR] Port {port} is CLOSED")
        return False
    sock.close()

if __name__ == "__main__":
    p5000 = check_port(5000)
    p5173 = check_port(5173)
    
    if not p5000 or not p5173:
        sys.exit(1)
