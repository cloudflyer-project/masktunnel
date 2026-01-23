"""Tests for masktunnel Python bindings."""

import pytest


class TestImport:
    """Test basic import functionality."""

    def test_import_masktunnel(self):
        """Test that masktunnel can be imported."""
        import masktunnel
        assert hasattr(masktunnel, "__version__")
        assert hasattr(masktunnel, "Server")
        assert hasattr(masktunnel, "set_log_level")

    def test_import_server(self):
        """Test that Server can be imported."""
        from masktunnel import Server
        assert Server is not None

    def test_version(self):
        """Test that version is a string."""
        import masktunnel
        assert isinstance(masktunnel.__version__, str)
        assert len(masktunnel.__version__) > 0


class TestServer:
    """Test Server class functionality."""

    def test_server_creation(self):
        """Test that Server can be created."""
        from masktunnel import Server
        server = Server()
        assert server is not None
        server.stop()

    def test_server_addr(self):
        """Test that Server has an address."""
        from masktunnel import Server
        server = Server()
        addr = server.addr
        assert isinstance(addr, str)
        assert len(addr) > 0
        server.stop()

    def test_server_ca_pem(self):
        """Test that Server can return CA PEM."""
        from masktunnel import Server
        server = Server()
        ca_pem = server.get_ca_pem()
        assert isinstance(ca_pem, bytes)
        assert len(ca_pem) > 0
        server.stop()

    def test_server_close(self):
        """Test that Server can be closed."""
        from masktunnel import Server
        server = Server()
        server.close()

    def test_server_reset_sessions(self):
        """Test that Server can reset sessions."""
        from masktunnel import Server
        server = Server()
        count = server.reset_sessions()
        assert isinstance(count, int)
        assert count >= 0
        server.stop()


class TestServerOptions:
    """Test ServerOptions functionality."""

    def test_server_options_creation(self):
        """Test that ServerOptions can be created."""
        from masktunnel._server import ServerOptions
        options = ServerOptions()
        assert options is not None

    def test_server_options_defaults(self):
        """Test ServerOptions default values."""
        from masktunnel._server import ServerOptions
        options = ServerOptions()
        assert options.addr == ""
        assert options.port == "8080"
        assert options.user_agent == ""
        assert options.payload == ""
        assert options.upstream_proxy == ""
        assert options.username == ""
        assert options.password == ""
        assert options.verbose == 0

    def test_server_with_options(self):
        """Test Server creation with custom options."""
        from masktunnel import Server
        from masktunnel._server import ServerOptions
        
        options = ServerOptions(port="9090", verbose=1)
        server = Server(options=options)
        assert server is not None
        server.stop()


class TestUtils:
    """Test utility functions."""

    def test_set_log_level(self):
        """Test that set_log_level can be called."""
        from masktunnel import set_log_level
        # Should not raise
        set_log_level(0)
        set_log_level(1)
        set_log_level(2)
