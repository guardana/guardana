"""The CI templates, held to the three things a copied pipeline gets wrong.

These files are meant to be copied into somebody else's repository, which makes
them documentation that executes. Nothing here can run a GitLab or a Jenkins, so
this asserts the properties that decide whether the pipeline is honest — and each
one is a mistake that has shipped in somebody's CI template before:

1. the exit code reaches the platform, so a finding fails the build;
2. the report is published *when the gate fails*, which is the only run anybody
   needs it for;
3. the entrypoint is overridden where the platform wraps commands in a shell,
   because otherwise the job dies with a usage error that looks like ours.

The image tag is not checked here — `test_release_tooling.py` holds every
documented tag to the released series, these files included.
"""

from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[3]
_CI = _REPO / "deploy" / "ci"
_GITLAB = _CI / "gitlab-ci.yml"
_AZURE = _CI / "azure-pipelines.yml"
_JENKINS = _CI / "Jenkinsfile"
_TEMPLATES = (_GITLAB, _AZURE, _JENKINS)
# Every way a platform is told "this failure does not count". A template that
# needs one of these has stopped being a gate.
_SWALLOWS_THE_GATE = ("allow_failure: true", "continueOnError: true", "|| true", "catchError")


def _instructions(path: Path) -> str:
    """The template without its comments — a warning about `|| true` is not a `|| true`."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return "\n".join(line for line in lines if not line.lstrip().startswith(("#", "//")))


@pytest.mark.parametrize("template", [_GITLAB, _AZURE], ids=["gitlab", "azure"])
def test_the_yaml_templates_parse(template: Path) -> None:
    """A template that does not load is a support request, not an integration."""
    assert yaml.safe_load(template.read_text(encoding="utf-8"))


@pytest.mark.parametrize("template", _TEMPLATES, ids=["gitlab", "azure", "jenkins"])
def test_no_template_swallows_the_exit_code(template: Path) -> None:
    """The exit code is the gate. `2` especially: "could not check" is not "fine"."""
    body = _instructions(template)

    swallowed = [marker for marker in _SWALLOWS_THE_GATE if marker in body]

    assert not swallowed, f"{template.name} neutralises the gate with {swallowed}"


def test_gitlab_keeps_the_report_when_the_gate_fails() -> None:
    document = yaml.safe_load(_GITLAB.read_text(encoding="utf-8"))

    artifacts = document["guardana"]["artifacts"]
    assert artifacts["when"] == "always", "a red pipeline would discard its own evidence"
    assert artifacts["reports"]["junit"] in artifacts["paths"]


def test_azure_publishes_the_report_when_the_gate_fails() -> None:
    document = yaml.safe_load(_AZURE.read_text(encoding="utf-8"))

    publishing = [step for step in document["steps"] if "condition" in step]
    assert publishing, "no step publishes anything"
    for step in publishing:
        assert step["condition"] == "always()", f"{step.get('displayName')} skips failed runs"


def test_jenkins_publishes_the_report_when_the_gate_fails() -> None:
    body = _instructions(_JENKINS)

    assert "post {" in body, "nothing runs after the stages"
    assert "always {" in body, "publishing is not in an always block"
    assert "junit " in body, "the JUnit report is never published"


@pytest.mark.parametrize(
    ("template", "override"),
    [(_GITLAB, 'entrypoint: [""]'), (_JENKINS, '--entrypoint=""')],
    ids=["gitlab", "jenkins"],
)
def test_the_platforms_that_wrap_commands_override_the_entrypoint(
    template: Path, override: str
) -> None:
    """`ENTRYPOINT` is `guardana`, so the runner would execute `guardana sh -c …`."""
    assert override in _instructions(template), f"{template.name} does not override the entrypoint"


@pytest.mark.parametrize("template", _TEMPLATES, ids=["gitlab", "azure", "jenkins"])
def test_every_template_produces_the_report_it_publishes(template: Path) -> None:
    """The filename in the scan and the filename in the artifact must be one file."""
    body = _instructions(template)

    assert body.count("guardana-junit.xml") >= 2, (
        f"{template.name} either does not write the report or does not publish it"
    )


def test_no_template_puts_a_credential_on_the_command_line() -> None:
    """A key in a command line lands in shell history and in most CI logs."""
    for template in _TEMPLATES:
        body = _instructions(template)
        assert "--api-key" not in body
        assert "gdn_" not in body
