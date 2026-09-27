from __future__ import annotations

from copy import deepcopy

import pytest

from codex_plugin_scanner.guard.native_command_model import _canonical_command_from_native
from tests.native_command_test_support import real_native_review_fixture


def _model() -> tuple[str, dict]:
    command = "sudo --command-timeout 10 git push origin main --force"
    return command, {
        "normalized_text": command,
        "dialect": "posix",
        "transport": "shell_string",
        "extraction_provenance": "guard-shell",
        "wrapper_chain": ["sudo"],
        "segments": [
            {
                "text": command,
                "tokens": command.split(),
                "executable": "git",
                "arguments": ["push", "origin", "main", "--force"],
                "environment_names": [],
                "wrapper_chain": ["sudo"],
                "path_overridden": False,
                "execution_context": "top:0",
                "pipeline_index": 0,
                "span": {"source": "normalized", "start": 0, "end": len(command)},
            }
        ],
        "confidence": "exact",
        "uncertainty_reason": None,
        "path_overridden": False,
        "parser_profile": "posix-bounded-wrappers-v2",
    }


def test_request_bound_wrapper_provenance_survives_conversion() -> None:
    command, model = _model()
    canonical = _canonical_command_from_native(command, model)
    assert canonical is not None
    assert canonical.normalized_text == command
    assert canonical.wrapper_chain == ("sudo",)
    assert canonical.segments[0].wrapper_chain == ("sudo",)
    assert canonical.segments[0].tokens == tuple(command.split())
    assert canonical.segments[0].executable == "git"
    assert canonical.segments[0].arguments[-1] == "--force"


@pytest.mark.parametrize(
    "command",
    [
        "exec simgit gc --discard-dirty",
        "xargs -I {} sg gc --delete-unmerged {}",
        "env -i PATH=/custom command -p sg remove --discard-dirty tree",
        "bash -c 'exec simgit gc $FLAGS'",
    ],
)
def test_native_simgit_wrapper_model_survives_python_bridge(command: str) -> None:
    native = real_native_review_fixture(command).payload["command_model"]
    canonical = _canonical_command_from_native(command, native)
    assert canonical is not None
    assert canonical.confidence == "exact"
    assert canonical.segments[0].executable in {"simgit", "sg"}
    assert canonical.wrapper_chain


@pytest.mark.parametrize(
    "mutation",
    [
        "legacy-profile",
        "missing-wrapper",
        "wrong-wrapper",
        "unknown-option",
        "invalid-timeout",
        "executable",
        "span",
        "dialect",
    ],
)
def test_mismatched_wrapper_evidence_is_rejected(mutation: str) -> None:
    command, original = _model()
    model = deepcopy(original)
    segment = model["segments"][0]
    if mutation == "legacy-profile":
        model["parser_profile"] = "posix-simple-v1"
    elif mutation == "missing-wrapper":
        model["wrapper_chain"] = []
    elif mutation == "wrong-wrapper":
        segment["wrapper_chain"] = ["env"]
    elif mutation == "unknown-option":
        segment["tokens"][1] = "--shell"
    elif mutation == "invalid-timeout":
        segment["tokens"][2] = "payload"
    elif mutation == "executable":
        segment["executable"] = "true"
    elif mutation == "span":
        segment["span"]["start"] = 1
    elif mutation == "dialect":
        model["dialect"] = "powershell"
    assert _canonical_command_from_native(command, model) is None
