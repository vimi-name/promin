from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from promin import service as service_runtime
from promin.contracts import ContractError, load_contract_bundle, validate_definition

# This test exercises the existing max-batch EventStore fixture.  It does not
# introduce a reduced Event shape or a separate validator path.
from test_heavy_event_batching import (  # type: ignore[import-not-found]
    NOW,
    POLICY,
    _command,
    _reads_relations,
    _store,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PRESET = PACKAGE_ROOT / "presets" / "semantic-standard.json"


def _max_batch_events(tmp_path: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    store = _store(tmp_path / "events")
    try:
        command = _command(1)
        relations = _reads_relations(command["payload"]["task_id"], 127)
        result = store.commit(command, auxiliary_relations=relations, created_at=NOW)
        envelope = store.read_envelope(result["batch_digest"])
        events = envelope["batch"]["events"]
        assert len(events) == POLICY.max_events_per_batch == 128
        return command, events
    finally:
        store.close()


def _validation_error(
    callback: object,
    value: dict[str, object],
    command: dict[str, object],
) -> str:
    with pytest.raises(ContractError) as captured:
        callback(value, evaluation_time=NOW, command=command)  # type: ignore[operator]
    return str(captured.value)


def test_max_event_batch_uses_precompiled_event_validator_without_schema_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 128-event callback batch cannot compile one JSON Schema per Event."""

    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    monkeypatch.setattr(service_runtime, "_validation_context", lambda _context: {})
    monkeypatch.setattr(service_runtime, "validate_ingress", lambda *_args, **_kwargs: None)
    validators = service_runtime._event_store_validators(
        SimpleNamespace(bundle=bundle)
    )
    command, events = _max_batch_events(tmp_path)
    bundle.definition_validator("Event")
    # The production max batch has one Task plus 127 Relation events.  This
    # callback-level test supplies the same 128-event contour with a valid
    # Relation payload at every position so that the Event schema path, rather
    # than Task construction, is the one under measurement.
    relation_payloads = [event["payload"] for event in events[1:]]
    valid_events = [
        {
            **event,
            "event_kind": "relation.recorded",
            "payload": relation_payloads[index % len(relation_payloads)],
        }
        for index, event in enumerate(events)
    ]

    invalid = {**valid_events[0], "event_id": 7}
    expected_error = _validation_error(
        lambda value, **_kwargs: validate_definition(
            bundle.schema,
            "Event",
            value,
        ),
        invalid,
        command,
    )

    # The assertion is intentionally after the valid/invalid baseline has
    # been established.  Any Event callback that constructs a new validator
    # now fails immediately, while a callback that obtains the already cached
    # ContractBundle validator retains exactly the same schema result.
    with mock.patch(
        "promin.contracts.validator_for",
        side_effect=AssertionError("Event callback recompiled its schema"),
    ) as compiler:
        for event in valid_events:
            assert (
                validators["event_validator"](
                    event,
                    evaluation_time=NOW,
                    command=command,
                )
                is True
            )
            assert (
                validators["compiled_record_validator"](
                    "Event",
                    event,
                    evaluation_time=NOW,
                    operation="commit",
                )
                is True
            )
        assert (
            _validation_error(validators["event_validator"], invalid, command)
            == expected_error
        )

    compiler.assert_not_called()
