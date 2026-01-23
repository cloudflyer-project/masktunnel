"""
Command-line interface for masktunnel.

This module provides CLI commands for the masktunnel proxy tool.
"""

import asyncio
import logging
import platform
import sys
from typing import Optional

import click

from ._utils import _logger


def init_logging(level: int = logging.INFO) -> None:
    """Initialize logging configuration."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    _logger.setLevel(level)


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
@click.option("--verbose", "-v", count=True, help="Verbose logging (-v for info, -vv for debug)")
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
    from ._server import Server, ServerOptions

    async def main():
        # Setup logging
        if verbose == 0:
            log_level = logging.WARNING
        elif verbose == 1:
            log_level = logging.INFO
        else:
            log_level = logging.DEBUG
        
        init_logging(level=log_level)

        options = ServerOptions(
            addr=addr,
            port=port,
            username=username,
            password=password,
            payload=payload,
            upstream_proxy=upstream_proxy,
            user_agent=user_agent,
            verbose=verbose,
        )

        srv = Server(options=options)
        
        click.echo(f"MaskTunnel proxy server running on {srv.addr}")
        click.echo("Press Ctrl+C to stop")

        # Start server in background thread
        await srv.async_start()

        try:
            # Wait forever until interrupted
            await asyncio.Future()
        except asyncio.CancelledError:
            pass
        finally:
            click.echo("\nShutting down...")
            await srv.async_stop()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        click.echo("\nShutting down...")


@click.command()
@click.option("--port", "-p", default="8080", help="Proxy listen port")
@click.option("--addr", "-a", default="", help="Proxy listen address")
@click.option("--output", "-o", default="ca.pem", help="Output file for CA certificate")
def get_ca(port: str, addr: str, output: str):
    """Get the CA certificate from a running server or generate a new one."""
    from ._server import Server, ServerOptions

    options = ServerOptions(addr=addr, port=port)
    srv = Server(options=options)
    
    ca_pem = srv.get_ca_pem()
    srv.stop()
    
    if ca_pem:
        with open(output, "wb") as f:
            f.write(ca_pem)
        click.echo(f"CA certificate saved to {output}")
    else:
        click.echo("Failed to get CA certificate", err=True)
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
