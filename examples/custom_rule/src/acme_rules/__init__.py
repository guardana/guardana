"""Acme's private Guardana rules and evaluator, discovered via entry points.

This package is a runnable example of the "extend Guardana in your own repo"
story: a third-party distribution with its own namespace (`acme.*`) shipping
two Python plugin rules, two declarative YAML rules, and a custom Evaluator
(classifier) — following the exact contract Guardana's own built-ins use.

`approved_model.py` is the one to read if you want to inspect a *model file*:
it is pure policy, because `guardana.core.formats` does the binary parsing —
bounded, offline, and fail-closed — so the rule never touches a byte offset.

Nothing here is special-cased: `guardana scan`/`probe`/`monitor` discover these
through the public `guardana.rules` and `guardana.evaluators` entry points
exactly as they discover the built-ins.
"""

import importlib.resources

from guardana.core.evaluator import Evaluator
from guardana.core.rule import Rule
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.core.target import Target
from guardana.core.taxonomy import TaxonomyRef

from acme_rules.approved_model import ApprovedModelRule
from acme_rules.controls import ACME_14
from acme_rules.hardcoded_secret import HardcodedAcmeKeyRule
from acme_rules.prompt_library_target import AcmePromptLibraryTarget
from acme_rules.refusal_classifier import StrictRefusalClassifier


def provide_evaluators() -> list[Evaluator]:
    """Entry point target for `guardana.evaluators`: Acme's custom classifier."""
    return [StrictRefusalClassifier()]


def provide_targets() -> list[type[Target]]:
    """Entry point target for `guardana.targets`: Acme's prompt library.

    The third group in the contract table, and the one nothing here registered until
    0.18.1 — which is how `pack validate` shipped accusing every pack with a target
    of not registering it, with no example able to notice.
    """
    return [AcmePromptLibraryTarget]


def provide_taxonomies() -> list[TaxonomyRef]:
    """Entry point target for `guardana.taxonomies`: Acme's own control catalogue.

    The fourth group, and the last one nothing registered. It was documented in
    `README.md`, `FEATURES.md` and `docs/usage-taxonomy.md` while
    `entry_points(group="guardana.taxonomies")` returned an empty list — the exact
    state `guardana.targets` was in one release earlier, when `pack validate`
    shipped accusing every pack with a target of not registering it and nothing
    could notice. A documented seam with no user is a seam nobody has run.

    `refusal.yaml` writes `taxonomy: [ACME-14]`, so this is load-bearing rather
    than decorative: the reference resolves only because discovery registers
    taxonomies before it loads rules.
    """
    return [ACME_14]


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
    return [HardcodedAcmeKeyRule(), ApprovedModelRule(), *_load_catalog_rules()]
