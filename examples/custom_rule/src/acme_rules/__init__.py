"""Acme's private Guardana rules and evaluator, discovered via entry points.

This package is a runnable example of the "extend Guardana in your own repo"
story: a third-party distribution with its own namespace (`acme.*`) shipping
one Python plugin rule, two declarative YAML rules, and a custom Evaluator
(classifier) — following the exact contract Guardana's own built-ins use.

Nothing here is special-cased: `guardana scan`/`probe`/`monitor` discover these
through the public `guardana.rules` and `guardana.evaluators` entry points
exactly as they discover the built-ins.
"""

import importlib.resources

from guardana.core.evaluator import Evaluator
from guardana.core.rule import Rule
from guardana.core.rule.yaml_rule import load_yaml_rules

from acme_rules.hardcoded_secret import HardcodedAcmeKeyRule
from acme_rules.refusal_classifier import StrictRefusalClassifier


def provide_evaluators() -> list[Evaluator]:
    """Entry point target for `guardana.evaluators`: Acme's custom classifier."""
    return [StrictRefusalClassifier()]


def _load_catalog_rules() -> list[Rule]:
    # A third-party package mixes built-in and custom evaluators freely: the
    # `overreach` rule reuses Guardana's `keyword`, while `refusal` grades with
    # Acme's own `acme.strict_refusal` — each referenced by id and resolved from
    # the registry at run time, no lookup wiring of its own.
    catalog_dir = importlib.resources.files("acme_rules.catalog")
    rules: list[Rule] = []
    for entry in sorted(catalog_dir.iterdir(), key=lambda p: p.name):
        if entry.name.endswith(".yaml"):
            with importlib.resources.as_file(entry) as path:
                rules.extend(load_yaml_rules(path))
    return rules


def provide_rules() -> list[Rule]:
    """Entry point target for `guardana.rules`: every rule Acme ships."""
    return [HardcodedAcmeKeyRule(), *_load_catalog_rules()]
