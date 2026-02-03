"""
MaskTunnel HTTP MITM proxy server implementation.

This module provides the Server class for running an HTTP MITM proxy server
with browser fingerprint simulation capabilities.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from ._base import (
    _logger,
    BufferZerologLogger,
    backend,
)


class Server:
    """MaskTunnel HTTP MITM proxy server.
    
    The Server class provides an HTTP MITM proxy with browser fingerprint
    simulation capabilities. It can intercept and modify HTTP/HTTPS traffic
    while mimicking real browser behavior.
    """

    def __init__(
        self,
        *,
        logger: Optional[logging.Logger] = None,
        addr: Optional[str] = None,
        port: Optional[int] = None,
        user_agent: Optional[str] = None,
        payload: Optional[str] = None,
        upstream_proxy: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verbose: Optional[bool] = None,
    ) -> None:
        """Initialize the MaskTunnel proxy server.
        
        Args:
            logger: Python logger instance for this server
            addr: Server listen address
            port: Server listen port
            user_agent: User agent string for browser simulation
            payload: Custom payload for fingerprint simulation
            upstream_proxy: Upstream proxy address for chaining
            username: Username for proxy authentication
            password: Password for proxy authentication
            verbose: Enable verbose logging
        """
        opt = backend.DefaultServerOption()
        if logger is None:
            logger = _logger
        # Use buffer-based logger system
        self._managed_logger = BufferZerologLogger(logger, f"server_{id(self)}")
        opt.WithLogger(self._managed_logger.go_logger)
        if addr is not None:
            opt.WithAddr(addr)
        if port is not None:
            opt.WithPort(int(port))
        if user_agent is not None:
            opt.WithUserAgent(user_agent)
        if payload is not None:
            opt.WithPayload(payload)
        if upstream_proxy is not None:
            opt.WithUpstreamProxy(upstream_proxy)
        if username is not None:
            opt.WithUsername(username)
        if password is not None:
            opt.WithPassword(password)
        if verbose is not None:
            opt.WithVerbose(bool(verbose))

        self._raw = backend.NewMaskTunnelServer(opt)

    @property
    def log(self) -> logging.Logger:
        """Access the Python logger for this server instance."""
        return self._managed_logger.py_logger

    @property
    def addr(self) -> str:
        """Get the server's listening address."""
        return self._raw.Addr()

    def start(self) -> None:
        """Start the server (blocking).
        
        This method blocks until the server is stopped.
        """
        try:
            self._raw.Start()
        except RuntimeError as e:
            if "Server closed" not in str(e):
                raise

    async def async_start(self) -> None:
        """Start the server asynchronously (blocking).
        
        This method blocks until the server is stopped.
        """
        await asyncio.to_thread(self.start)

    def start_background(self) -> None:
        """Start the server in background (non-blocking).

        After this method returns, the server is ready to accept connections
        and the addr property will return the actual listening address.
        """
        self._raw.StartBackground()

    async def async_start_background(self) -> None:
        """Start the server in background asynchronously (non-blocking)."""
        await asyncio.to_thread(self._raw.StartBackground)

    def stop(self) -> None:
        """Stop the server."""
        self._raw.Stop()

    async def async_stop(self) -> None:
        """Stop the server asynchronously."""
        await asyncio.to_thread(self._raw.Stop)

    def reset_sessions(self) -> None:
        """Reset all active sessions."""
        self._raw.ResetSessions()

    async def async_reset_sessions(self) -> None:
        """Reset all active sessions asynchronously."""
        await asyncio.to_thread(self._raw.ResetSessions)

    def set_upstream_proxy(self, proxy_url: str) -> None:
        """Set upstream proxy for the server.
        
        Args:
            proxy_url: Upstream proxy URL
        """
        self._raw.SetUpstreamProxy(proxy_url)

    async def async_set_upstream_proxy(self, proxy_url: str) -> None:
        """Set upstream proxy for the server asynchronously.
        
        Args:
            proxy_url: Upstream proxy URL
        """
        await asyncio.to_thread(self._raw.SetUpstreamProxy, proxy_url)

    def get_ca_pem(self) -> str:
        """Get the CA certificate in PEM format.
        
        Returns:
            CA certificate PEM string
        """
        return self._raw.GetCAPEM()

    async def async_get_ca_pem(self) -> str:
        """Get the CA certificate in PEM format asynchronously.
        
        Returns:
            CA certificate PEM string
        """
        return await asyncio.to_thread(self._raw.GetCAPEM)

    def close(self) -> None:
        """Close the server and clean up resources."""
        # Close server
        if hasattr(self, '_raw') and self._raw:
            self._raw.Close()
        # Clean up managed logger
        if hasattr(self, '_managed_logger') and self._managed_logger:
            try:
                self._managed_logger.cleanup()
            except:
                # Ignore cleanup errors
                pass

    async def async_close(self) -> None:
        """Close the server and clean up resources asynchronously."""
        # Close server
        if hasattr(self, '_raw') and self._raw:
            await asyncio.to_thread(self._raw.Close)
        # Clean up managed logger
        if hasattr(self, '_managed_logger') and self._managed_logger:
            try:
                self._managed_logger.cleanup()
            except:
                # Ignore cleanup errors
                pass
    
    def __enter__(self) -> "Server":
        """Context manager entry."""
        self.start_background()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        """Context manager exit."""
        self.close()
        
    async def __aenter__(self) -> "Server":
        """Async context manager entry."""
        await self.async_start_background()
        return self
        
    async def __aexit__(self, exc_type, exc, tb) -> None:
        """Async context manager exit."""
        await self.async_close()
        
    def __del__(self):
        """Destructor - clean up resources."""
        try:
            self.close()
        except Exception:
            # Ignore errors during cleanup
            pass
