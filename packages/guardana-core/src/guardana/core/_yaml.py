"""Safely construct YAML while preserving source context for malformed scalars."""

import yaml


class ScalarSafeLoader(yaml.SafeLoader):
    """Report malformed scalar construction through PyYAML's marked error type."""

    def construct_object(self, node: yaml.Node, deep: bool = False) -> object:
        """Construct a node, preserving source context when scalar conversion fails."""
        try:
            value: object = super().construct_object(node, deep)
        except yaml.constructor.ConstructorError as exc:
            if isinstance(node, yaml.ScalarNode):
                exc.problem = f"{exc.problem}: {node.value!r}"
            raise
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            if not isinstance(node, yaml.ScalarNode):
                raise
            problem = f"{exc}: {node.value!r}"
            raise yaml.constructor.ConstructorError(None, None, problem, node.start_mark) from exc
        return value


def load_yaml(text: str) -> object:
    """Read one safe YAML document, raising YAML errors for malformed scalars."""
    loader = ScalarSafeLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()
