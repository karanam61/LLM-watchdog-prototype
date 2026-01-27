
import socket
import sys

def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex(('127.0.0.1', port))
    if result == 0:
        print(f"PORT {port}: OPEN")
        return True
    else:
        print(f"PORT {port}: CLOSED")
        return False
    sock.close()

if __name__ == "__main__":
    check_port(5000)
