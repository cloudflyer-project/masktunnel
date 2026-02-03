"""Command-line interface for masktunnel.

This module provides CLI commands for the masktunnel proxy tool.
"""

import asyncio
import logging
import platform
import sys
from typing import Optional

import click
from loguru import logger

from ._logging_config import init_logging
from ._utils import _stop_log_listener


@click.group()
def cli():
    """MaskTunnel - Smart proxy with browser fingerprint simulation."""
    pass


@click.command()
def version():
    """Print version and platform information."""
    try:
        from masktunnel import __version__
        version_str = __version__
    except ImportError:
        version_str = "unknown"
    
    platform_str = platform.platform()
    click.echo(f"masktunnel version {version_str} {platform_str}")


@click.command()
@click.option("--port", "-p", default="8080", help="Proxy listen port")
@click.option("--addr", "-a", default="", help="Proxy listen address")
@click.option("--username", "-u", default="", help="Proxy authentication username")
@click.option("--password", "-w", default="", help="Proxy authentication password")
@click.option("--payload", "-j", default="", help="JavaScript to inject into responses")
@click.option("--upstream-proxy", "-x", default="", help="Upstream proxy URL")
@click.option("--user-agent", "-U", default="", help="Override User-Agent header")
@click.option("--verbose", "-v", count=True, help="Verbose logging (-v for debug, -vv for more)")
def server(
    port: str,
    addr: str,
    username: str,
    password: str,
    payload: str,
    upstream_proxy: str,
    user_agent: str,
    verbose: int,
):
    """Start MaskTunnel proxy server."""
    from ._server import Server

    # Setup logging (match linksocks behavior: show startup info by default)
    if verbose == 0:
        log_level = logging.INFO
    elif verbose == 1:
        log_level = logging.DEBUG
    else:
        log_level = logging.DEBUG
    
    init_logging(level=log_level)

    srv = Server(
        addr=addr,
        port=int(port) if port else 8080,
        username=username or None,
        password=password or None,
        payload=payload or None,
        upstream_proxy=upstream_proxy or None,
        user_agent=user_agent or None,
        verbose=verbose > 0,
    )

    async def _run() -> None:
        async with srv:
            logger.info(f"MaskTunnel proxy server running on {srv.addr}")
            logger.info("Press Ctrl+C to stop")
            await asyncio.Future()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        # Let the async context manager perform cleanup.
        pass
    finally:
        _stop_log_listener()


@click.command()
@click.option("--port", "-p", default="8080", help="Proxy listen port")
@click.option("--addr", "-a", default="", help="Proxy listen address")
@click.option("--output", "-o", default="ca.pem", help="Output file for CA certificate")
def get_ca(port: str, addr: str, output: str):
    """Get the CA certificate from a running server or generate a new one."""
    from ._server import Server

    init_logging(level=logging.WARNING)

    srv = Server(addr=addr or None, port=int(port) if port else 8080)
    ca_pem = srv.get_ca_pem()
    srv.close()
    _stop_log_listener()
    
    if ca_pem:
        with open(output, "wb") as f:
            f.write(ca_pem)
        logger.info(f"CA certificate saved to {output}")
    else:
        logger.error("Failed to get CA certificate")
        sys.exit(1)


# Register commands
cli.add_command(version)
cli.add_command(server)
cli.add_command(get_ca)


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
