"""Property tests (§13.1): canonical form, digests, encoding round trips."""

from __future__ import annotations

import base64
import copy
import json

from hypothesis import given, settings
from hypothesis import strategies as st

from agentguard.core.canonical import canonical_dumps, loads_strict
from agentguard.core.index import ValueIndex, decode_candidates, normalize_text
from agentguard.core.lock import full_digest

json_values = st.recursive(
    st.none() | st.booleans() | st.integers(-(10**6), 10**6) | st.text(max_size=20),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4)
    ),
    max_leaves=15,
)


@given(json_values)
def test_canonical_form_is_stable_under_reparsing(value: object) -> None:
    once = canonical_dumps(value)
    assert canonical_dumps(loads_strict(once)) == once


@given(st.dictionaries(st.text(min_size=1, max_size=6), st.integers(), min_size=2, max_size=6))
def test_key_order_does_not_change_the_digest(mapping: dict[str, int]) -> None:
    tool = {"name": "t", **{f"k{key}": value for key, value in mapping.items()}}
    shuffled = dict(reversed(list(tool.items())))
    assert full_digest(tool) == full_digest(shuffled)


@given(st.text(min_size=1, max_size=40), st.integers(0, 39))
def test_any_single_character_change_changes_the_digest(description: str, position: int) -> None:
    tool = {"name": "t", "description": description}
    changed = copy.deepcopy(tool)
    index = position % len(description)
    replacement = "a" if description[index] != "a" else "b"
    changed["description"] = description[:index] + replacement + description[index + 1 :]
    assert full_digest(tool) != full_digest(changed)


@given(st.text(max_size=60))
def test_normalization_is_idempotent(text: str) -> None:
    once = normalize_text(text)
    assert normalize_text(once) == once


@settings(max_examples=60, deadline=None)
@given(st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126), min_size=30, max_size=120))
def test_encoded_values_are_still_found(secret: str) -> None:
    index = ValueIndex(100_000)
    index.add(secret, {"secret"}, "c_1")
    wrappers = [
        base64.b64encode(secret.encode()).decode(),
        base64.urlsafe_b64encode(secret.encode()).decode(),
        secret.encode().hex(),
    ]
    for encoded in wrappers:
        decoded, _ = decode_candidates(encoded, 100_000)
        assert any(index.find(candidate, {"secret"}, 1) for candidate in [encoded, *decoded]), encoded


def test_number_literals_survive_a_round_trip() -> None:
    text = '{"a":1.0,"b":1e3,"c":10}'
    assert canonical_dumps(loads_strict(text)) == text
    assert json.loads(canonical_dumps(loads_strict(text))) == json.loads(text)
