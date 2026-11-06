"""Local relay working around error 1109 / 06B4.0000 in Apple Devices for Windows.

During an iPhone/iPad update or restore, Apple Devices downloads the AEA decryption key of the
system image from https://wkms-public.apple.com/fcs-keys/..., which redirects to Apple's CDN
fcs-keys-pub-prod.cdn-apple.com. The CDN sends its TLS 1.3 session tickets and the HTTP response
in the same packet, and Apple Devices' own TLS stack (CFNetwork.dll) then stalls until it times
out. This relay forwards the connection to the real CDN (TLS stays end-to-end, no certificate is
touched) and hands the TLS records to Apple Devices one at a time, with a short pause in between.

Usage:
  1. hosts file line (as administrator):  127.0.0.1 fcs-keys-pub-prod.cdn-apple.com
  2. ipconfig /flushdns
  3. python apple_key_relay.py      (keep it open during the update; Ctrl+C to quit)
  4. after the update remove the hosts line and run ipconfig /flushdns again
"""
import socket, struct, sys, threading, time

HOST = "fcs-keys-pub-prod.cdn-apple.com"
UPSTREAM = "fcs-keys.g.aaplimg.com"  # the CDN's CNAME: not affected by the hosts line
LISTEN = ("127.0.0.1", 443)
GAP = 0.05  # pause between TLS records delivered to Apple Devices


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def client_to_server(c, u):
    try:
        while d := c.recv(65536):
            u.sendall(d)
    except OSError:
        pass
    finally:
        try:
            u.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def server_to_client(u, c):
    """Forward one complete TLS record at a time to the client; return the number forwarded."""
    buf, count = b"", 0
    try:
        while d := u.recv(65536):
            buf += d
            while len(buf) >= 5 and len(buf) >= 5 + struct.unpack(">H", buf[3:5])[0]:
                n = 5 + struct.unpack(">H", buf[3:5])[0]
                c.sendall(buf[:n])
                buf = buf[n:]
                count += 1
                time.sleep(GAP)
        if buf:
            c.sendall(buf)
    except OSError:
        pass
    return count


def handle(c, peer):
    try:
        ip = socket.getaddrinfo(UPSTREAM, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        u = socket.create_connection((ip, 443), timeout=15)
        u.settimeout(None)
    except OSError as e:
        log(f"connection from port {peer[1]}: cannot reach {UPSTREAM}: {e}")
        c.close()
        return
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    log(f"connection from port {peer[1]} -> {UPSTREAM} ({ip})")
    threading.Thread(target=client_to_server, args=(c, u), daemon=True).start()
    n = server_to_client(u, c)
    log(f"connection from port {peer[1]} closed ({n} TLS records forwarded)")
    for s in (c, u):
        try:
            s.close()
        except OSError:
            pass


def main():
    try:
        resolved = socket.gethostbyname(HOST)
    except OSError:
        resolved = "?"
    if resolved != "127.0.0.1":
        log(f"WARNING: {HOST} resolves to {resolved}, not 127.0.0.1: the hosts line is missing "
            "or 'ipconfig /flushdns' is needed. Without it Apple Devices will not use the relay.")
    srv = socket.socket()
    try:
        srv.bind(LISTEN)
    except OSError as e:
        sys.exit(f"Cannot listen on {LISTEN[0]}:{LISTEN[1]}: {e}")
    srv.listen(16)
    srv.settimeout(1.0)
    log(f"relay running on {LISTEN[0]}:{LISTEN[1]} -> {UPSTREAM}. Start the update; Ctrl+C to quit.")
    try:
        while True:
            try:
                c, peer = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle, args=(c, peer), daemon=True).start()
    except KeyboardInterrupt:
        log("relay stopped")


if __name__ == "__main__":
    main()
