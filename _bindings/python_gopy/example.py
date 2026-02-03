"""Example: Using masktunnel with start_background() for non-blocking server."""

import asyncio
import logging
import socket
import time

from masktunnel import Server
from masktunnel._server import ServerOptions


def setup_logging():
    """Configure logging to see masktunnel internal logs."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logger = logging.getLogger("masktunnel")
    logger.setLevel(logging.DEBUG)
    return logger


def get_options():
    """Create server options with port=0 for OS-assigned port."""
    return ServerOptions(
        addr="127.0.0.1",
        port="0",
        verbose=1,  # 0=quiet, 1=info, 2=debug
    )


def verify_server(server: Server):
    """Verify the server is listening."""
    actual_addr = server.addr
    print(f"Server started at: {actual_addr}")
    
    host, port_str = actual_addr.rsplit(":", 1)
    port = int(port_str)
    
    time.sleep(0.5)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(2)
        sock.connect((host, port))
        print(f"Port {port} is listening!")
        sock.close()
    except Exception as e:
        print(f"Port {port} is NOT listening: {e}")


# =============================================================================
# Example 1: Manual start/stop
# =============================================================================
def example_manual():
    """Manual start_background() and close()."""
    print("\n=== Example 1: manual start/stop ===")
    logger = setup_logging()
    opts = get_options()
    
    server = Server(options=opts, logger=logger)
    server.start_background()
    
    verify_server(server)
    
    # Do your work here...
    time.sleep(2)
    
    server.close()
    print("Server closed.")


# =============================================================================
# Example 2: Using 'with' statement (context manager)
# =============================================================================
def example_with():
    """Using 'with' statement - auto start and close."""
    print("\n=== Example 2: with statement ===")
    logger = setup_logging()
    opts = get_options()
    
    with Server(options=opts, logger=logger) as server:
        verify_server(server)
        
        # Do your work here...
        time.sleep(2)
    
    # Server is automatically closed when exiting 'with' block
    print("Server closed automatically.")


# =============================================================================
# Example 3: Async version
# =============================================================================
async def example_async():
    """Async version with manual start/stop."""
    print("\n=== Example 3: async version ===")
    logger = setup_logging()
    opts = get_options()
    
    server = Server(options=opts, logger=logger)
    server.start_background()
    
    verify_server(server)
    
    # Do async work here...
    await asyncio.sleep(2)
    
    await server.async_close()
    print("Server closed.")


# =============================================================================
# Example 4: Using 'async with' statement (async context manager)
# =============================================================================
async def example_async_with():
    """Using 'async with' statement - auto start and close."""
    print("\n=== Example 4: async with statement ===")
    logger = setup_logging()
    opts = get_options()
    
    async with Server(options=opts, logger=logger) as server:
        verify_server(server)
        
        # Do async work here...
        await asyncio.sleep(2)
    
    # Server is automatically closed when exiting 'async with' block
    print("Server closed automatically.")


# =============================================================================
# Main
# =============================================================================
def main():
    # Run sync examples
    example_manual()
    example_with()
    
    # Run async examples
    asyncio.run(example_async())
    asyncio.run(example_async_with())


if __name__ == "__main__":
    main()
