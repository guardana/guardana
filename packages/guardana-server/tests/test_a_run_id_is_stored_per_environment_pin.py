"""A run stored under one environment pin never swallows a run another pin submits."""

from conftest import Scoped, _submission
from guardana.server.envelope import RunIn
from guardana.server.store import Added
from guardana.server.tenancy import TenantScope

_RUN = "4b8e2a6c-1d3f-4a5b-9c7e-0f2d4b6a8c1e"


def test_control_a_retried_run_under_the_same_pin_is_stored_once(scoped: Scoped) -> None:
    store, scope = scoped
    production = TenantScope.for_project(scope.require_project(), environment="production")

    first = store.add(production, _submission(run=RunIn(run_id=_RUN)))
    again = store.add(production, _submission(run=RunIn(run_id=_RUN)))

    assert (first, again) == (Added.STORED, Added.DUPLICATE)
    assert len(store.submissions(production)) == 1


def test_a_dev_run_never_hides_the_production_run_with_the_same_id(scoped: Scoped) -> None:
    store, scope = scoped
    project = scope.require_project()
    dev = TenantScope.for_project(project, environment="dev")
    production = TenantScope.for_project(project, environment="production")

    store.add(dev, _submission(run=RunIn(run_id=_RUN), findings=[]))
    stored = store.add(production, _submission(run=RunIn(run_id=_RUN)))

    held = store.submissions(production)
    assert stored is Added.STORED, "the production submission was answered as a duplicate"
    assert len(held) == 1
    assert held[0].findings
