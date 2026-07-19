from guardana.core.registry import Registry


def test_discover_loads_rules_entrypoint_without_error() -> None:
    # guardana-rules registers a `guardana.rules` entry point; discovery must succeed
    reg = Registry.discover()
    assert isinstance(reg.rules(), tuple)
