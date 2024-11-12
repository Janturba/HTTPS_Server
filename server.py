import ssl
import socket
import threading
import logging
import os
import argparse

logging.basicConfig(level=logging.DEBUG)

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(('www.google.com', 443))
            tuples = sock.getsockname()
            src_ip = tuples[0]
            return src_ip
    except Exception as e:
        logging.error(f"Failed to retrieve local IP: {e}")

class HTTPSServer():

    def __init__(self, host, port, proto):
        self.port = port
        self.host = host
        self.working_dir = os.getcwd()
        self.proto = proto

    def client_socket_handler(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self.proto == "http":
                s.bind((self.host, self.port))
                s.listen(10)
                print(f"Listening on {self.host}:{self.port}")

            else:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certfile=f'{self.working_dir}/certificate.pem',
                                        keyfile=f'{self.working_dir}/private.key')
                ssock = context.wrap_socket(s, server_side=True)
                ssock.bind((self.host, self.port))
                ssock.listen(10)
                print(f"Listening on {self.host}:{self.port}")

            while True:
                try:
                    if self.proto == "http":
                        conn, addr = s.accept()
                    else:
                        conn, addr = ssock.accept()
                    print(f"TCP socket open with {addr}")
                    client_thread = threading.Thread(target=self.client_handler, args=(conn,))
                    client_thread.start()
                except Exception as e:
                    logging.error(f"Error accepting connection: {e}")

    def client_handler(self, conn):
        try:
            with conn:
                if self.proto == "https":
                    conn.do_handshake()
                while True:
                    req = b''
                    while True:
                        chunk = conn.recv(1024)
                        if not chunk:  # Check for closed connection
                            logging.warning("Connection closed by client.")
                            return
                        req += chunk
                        delimiter = b'\r\n\r\n'
                        if delimiter in req:
                            break

                    lines = req.splitlines()
                    for line in lines:
                        print(line.decode())

                    if b"basic_auth" in req:
                        self.basic_auth(conn, req)
                        break
                    elif b"chunk_me" in req:
                        self.chunk_me(conn, req)
                        break
                    elif b"known_length" in req:
                        self.known_length(conn, req)
                        break
                    elif b"byte_ranges" in req:
                        self.byte_ranges(conn, req)
                        break
                    elif b"stream" in req:
                        self.stream(conn, req)
                        break
                    elif b"non_http" in req:
                        self.non_http(conn, req)
                    elif b"bloomberg_chunk" in req:
                        self.bloomberg_chunk(conn, req)
                    else:
                        self.home_dir(conn, req)
                        break
        except ssl.SSLEOFError as e:
            logging.error(f"SSL Error: {e}")
        except Exception as e:
            logging.error(f"General Error in client handler: {e}")

    def basic_auth(self, client_conn, resp):
        logging.debug("\n\t\BASIC_AUTH\t\n")
        try:
            http_resp = f"HTTP/1.1 401 Unauthorized\r\nServer: py\r\nConnection: close\r\nWWW-Authenticate: BASIC realm='lab'\r\n\r\n"
            client_conn.send(http_resp.encode())
        except ssl.SSLEOFError as e:
            logging.error(f"SSL Error in basic_auth: {e}")
        except Exception as e:
            logging.error(f"General Error in basic_auth: {e}")

    def home_dir(self, client_conn, resp):
        f = open("./home.html", 'r')
        home_page = f.read()
        size = len(home_page)
        logging.debug("\n\tHOME_DIR\t\n")
        http_resp = f"HTTP/1.0 200 OK\r\n" \
                    f"Server: py\r\n" \
                    f"Connection: close\r\n" \
                    f"Content-Length: {size + 4}\r\n" \
                    f"\r\n" \
                    f"{home_page}\r\n" \
                    f"\r\n"
        client_conn.send(http_resp.encode())

    def chunk_me(self, client_conn, resp):
        logging.debug("\n\tCHUNK_ME\t\n")
        http_resp = f"HTTP/1.0 200 OK\r\n" \
                    f"Server: py\r\n" \
                    f"Content-Type: text/plain\r\n" \
                    f"Transfer-Encoding: chunked\r\n" \
                    f"Connection: keep-alive\r\n" \
                    f"\r\n"
        client_conn.sendall(http_resp.encode())
        file_path = f'{self.working_dir}/large_dummy_file.txt'
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                chunk_size = f"{len(chunk):X}\r\n"
                logging.debug(f"Sending chunk of size: {len(chunk)}")
                client_conn.sendall(chunk_size.encode())
                client_conn.sendall(chunk)
                client_conn.sendall(b"\r\n")
        client_conn.sendall(b"0\r\n\r\n")
        logging.debug("Sent final zero-length chunk")

    def bloomberg_chunk(self, client_conn, resp):
        logging.debug("\n\tBLOOMBERG_CHUNK\t\n")
        http_resp = f"HTTP/1.0 200 OK\r\n" \
                    f"Server: py\r\n" \
                    f"Content-Type: text/plain\r\n" \
                    f"Transfer-Encoding: chunked\r\n" \
                    f"Connection: keep-alive\r\n" \
                    f"\r\n"
        client_conn.sendall(http_resp.encode())
        file_path = f'{self.working_dir}/large_dummy_file.txt'
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                chunk_size = f"{len(chunk):X}\r\n"
                logging.debug(f"Sending chunk of size: {len(chunk)}")
                client_conn.sendall(chunk_size.encode())
                client_conn.sendall(chunk)
        client_conn.sendall(b"\r")
        logging.debug("Sent final zero-length chunk")

    def known_length(self, client_conn, resp):
        logging.debug("\n\tKNOWN_LENGTH\t\n")
        file_path = f'{self.working_dir}/large_dummy_file.exe'
        f = open(file_path, 'rb')
        content = f.read()
        http_resp = f"HTTP/1.0 200 OK\r\n" \
                    f"Server: py\r\n" \
                    f"Content-Type: text/plain\r\n" \
                    f"Content_Length: {len(content)}\r\n" \
                    f"Connection: keep-alive\r\n" \
                    f"\r\n"
        client_conn.sendall(http_resp.encode())
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                logging.debug(f"Sending chunk of size: {len(chunk)}")
                client_conn.sendall(chunk)
        client_conn.sendall(b"\r\n\r\n")
        logging.debug("Sent final zero-length chunk")

    def byte_ranges(self, client_conn, resp):
        logging.debug("\n\tBYTE_RANGES\t\n")
        file_path = f'{self.working_dir}/large_dummy_file.txt'
        file_size = os.path.getsize(file_path)

        # Extract the Range header from the request
        range_header = self.extract_range_header(resp)

        # Parse the Range header
        if range_header is None:
            http_resp = f"HTTP/1.0 416 Range Not Satisfiable\r\n" \
                        f"Server: py\r\n" \
                        f"Connection: close\r\n" \
                        f"\r\n"
            client_conn.sendall(http_resp.encode())
            return

        start, end = range_header
        if start < 0 or end >= file_size or start > end:
            http_resp = f"HTTP/1.0 416 Range Not Satisfiable\r\n" \
                        f"Server: py\r\n" \
                        f"Connection: close\r\n" \
                        f"\r\n"
            client_conn.sendall(http_resp.encode())
            return

        # Prepare the response with Content-Range header
        content_length = end - start + 1
        http_resp = f"HTTP/1.0 206 Partial Content\r\n" \
                    f"Server: py\r\n" \
                    f"Content-Type: text/plain\r\n" \
                    f"Content-Range: bytes {start}-{end}/{file_size}\r\n" \
                    f"Content-Length: {content_length}\r\n" \
                    f"Connection: keep-alive\r\n" \
                    f"\r\n"
        client_conn.sendall(http_resp.encode())

        # Send the requested byte range
        with open(file_path, 'rb') as f:
            f.seek(start)  # Move to the start of the requested range
            chunk = f.read(content_length)  # Read the specified range
            logging.debug(f"Sending bytes {start}-{end} (length: {len(chunk)})")
            client_conn.sendall(chunk)

    def extract_range_header(self, req):
        """Extracts the byte range from the Range header in the request."""
        range_header = None
        for line in req.splitlines():
            if line.startswith(b"Range:"):
                range_value = line.split(b":")[1].strip()
                if range_value.startswith(b"bytes="):
                    # Remove 'bytes=' and split the range
                    range_value = range_value[6:]
                    start_end = range_value.split(b"-")
                    start = int(start_end[0]) if start_end[0] else 0
                    end = int(start_end[1]) if len(start_end) > 1 and start_end[1] else None
                    if end is None:
                        end = float('inf')  # Handle the case where end is not provided
                    return start, end
        return range_header

    def stream(self, client_conn, resp):
        logging.debug("\n\tKNOWN_LENGTH\t\n")
        http_resp = f"HTTP/1.0 200 OK\r\n" \
                    f"Server: py\r\n" \
                    f"Content-Type: stream\r\n" \
                    f"Connection: keep-alive\r\n" \
                    f"\r\n"
        client_conn.sendall(http_resp.encode())
        stream_size = 1048576000
        sent_bytes = 0
        binary_chunk = b'\x00' * 1024
        chunks = 0
        try:
            while sent_bytes <= stream_size:
                sent_bytes += 1024
                client_conn.sendall(binary_chunk)
                chunks += 1
            client_conn.sendall(b"\r\n\r\n")
        except  Exception as e:
            logging.debug(f"{e}\nTOTAL bytes sent: {sent_bytes}\nTotal chunks sent: {chunks}")
        logging.debug("Sent final zero-length chunk")

    def non_http(self, client_conn, resp):
        logging.debug("\n\tNON_HTTP\t\n")
        resp = f"foobar\r\n\r\n"
        client_conn.sendall(resp.encode())

def cli_wrapper():
    local_ip = get_local_ip()
    parser = argparse.ArgumentParser(description="Run a local HTTP/S server.")
    parser.add_argument('-lh', '--host', type=str, default=local_ip, help=f"Host IP to listen on (default: {local_ip}")
    parser.add_argument('-p', '--port', type=int, default=4443, help="Port to listen on (default: 4443)")
    parser.add_argument('-s', '--protocol', type=str, default="https", help="HTTP vs HTTPS listener (default: 'https'")

    args = parser.parse_args()
    if not local_ip == None:
        server = HTTPSServer(args.host, args.port, args.protocol)

        try:
            server.client_socket_handler()
        except KeyboardInterrupt:
            print("\nServer shutting down...")
            logging.info("Server stopped by user.")

if __name__ == '__main__':
    cli_wrapper()
