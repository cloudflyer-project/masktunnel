from __future__ import annotations


def test_version_is_string():
    import masktunnel

    assert isinstance(masktunnel.__version__, str)
    assert len(masktunnel.__version__) > 0


def test_server_creation_with_defaults():
    from masktunnel import Server

    server = Server()
    assert server is not None
    server.stop()


def test_server_creation_with_options():
    from masktunnel import Server

    server = Server(
        addr="127.0.0.1",
        port=9999,
        user_agent="TestAgent/1.0",
        verbose=True
    )
    assert server is not None
    server.stop()


def test_set_log_level_callable():
    from masktunnel import set_log_level

    set_log_level(0)
    set_log_level(1)
    set_log_level(2)
