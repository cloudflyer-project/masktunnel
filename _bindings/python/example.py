"""Example: Using masktunnel with start_background() for non-blocking server."""

import logging
import socket
import time

from masktunnel import Server
from masktunnel._server import ServerOptions


def main():
    # Configure logging to see masktunnel internal logs
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    
    # Create a custom logger for masktunnel (optional)
    # If not provided, masktunnel uses its default logger
    logger = logging.getLogger("masktunnel")
    logger.setLevel(logging.DEBUG)

    # Create server with port=0 to let OS assign a random available port
    opts = ServerOptions(
        addr="127.0.0.1",
        port="0",
        verbose=1,  # 0=quiet, 1=info, 2=debug
    )
    
    # Pass custom logger to Server
    server = Server(options=opts, logger=logger)

    # Start server in background (non-blocking)
    # After this returns, the server is ready and addr contains the actual port
    server.start_background()

    # Now we can get the actual listening address
    actual_addr = server.addr
    print(f"Server started at: {actual_addr}")

    # Parse the port
    host, port_str = actual_addr.rsplit(":", 1)
    port = int(port_str)
    print(f"Parsed - Host: {host}, Port: {port}")

    # Verify the port is listening
    time.sleep(0.5)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(2)
        sock.connect((host, port))
        print(f"Port {port} is listening!")
        sock.close()
    except Exception as e:
        print(f"Port {port} is NOT listening: {e}")

    print("Server will be running for 30 seconds.")
    time.sleep(30)

    # Stop the server (same as blocking mode)
    server.stop()
    print("Server stopped.")

    # Or use close() which also cleans up resources
    server.close()
    print("Server closed and resources cleaned up.")


if __name__ == "__main__":
    main()
