from __future__ import annotations


def test_version_is_string():
    import masktunnel

    assert isinstance(masktunnel.__version__, str)
    assert len(masktunnel.__version__) > 0


def test_server_options_defaults():
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


def test_set_log_level_callable():
    from masktunnel import set_log_level

    set_log_level(0)
    set_log_level(1)
    set_log_level(2)
