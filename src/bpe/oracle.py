"""Typed, deterministic XDP differential-oracle contracts.

This module is deliberately execution-free.  A trusted runner may produce raw traces,
but comparison, normalization, map-delta derivation, and report verification are pure
functions over strict, content-addressed records.
"""

from __future__ import annotations

from itertools import pairwise
from typing import Annotated, Literal, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

from bpe.canonical import sha256_json
from bpe.models import Sha256, StableId

MAX_ORACLE_CASES = 256
MAX_ASSERTIONS_PER_CASE = 256
MAX_COLLECTION_ITEMS = 16_384
MAX_OBSERVATION_BYTES = 16 * 1024 * 1024
MAX_TRACE_OBSERVATION_BYTES = 128 * 1024 * 1024
MAX_NORMALIZATIONS_PER_CASE = 256

HexBytes = Annotated[
    str,
    Field(
        pattern=r"^(?:[0-9a-f]{2})*$",
        max_length=MAX_OBSERVATION_BYTES * 2,
    ),
]
NonEmptyHexBytes = Annotated[
    str,
    Field(
        pattern=r"^(?:[0-9a-f]{2})+$",
        min_length=2,
        max_length=MAX_OBSERVATION_BYTES * 2,
    ),
]
Unsigned32 = Annotated[int, Field(ge=0, le=(1 << 32) - 1)]
Unsigned64 = Annotated[int, Field(ge=0, le=(1 << 64) - 1)]
CounterDelta = Annotated[int, Field(ge=-(1 << 64) + 1, le=(1 << 64) - 1)]


class OracleContractError(ValueError):
    """An oracle contract, trace, or supplied report is not admissible."""


class _OracleModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
        strict=True,
    )


class ContentIdentity(_OracleModel):
    """Exact byte identity for a program or stored case fixture."""

    sha256: Sha256
    size_bytes: Annotated[int, Field(ge=1, le=MAX_OBSERVATION_BYTES)]
    media_type: Annotated[str, Field(min_length=1, max_length=127)]


class XdpCaseInput(_OracleModel):
    """The exact stored input supplied independently to both program executions."""

    fixture: ContentIdentity
    driver: Literal["bpf_prog_run/xdp@1"]
    repeat: Literal[1]


class _Assertion(_OracleModel):
    assertion_id: StableId
    required: bool = True
    weight: Annotated[float, Field(gt=0, le=1_000_000)] = 1.0


class RetvalAssertion(_Assertion):
    kind: Literal["retval"]


class PacketBytesAssertion(_Assertion):
    kind: Literal["packet_bytes"]


class ContextBytesAssertion(_Assertion):
    kind: Literal["context_bytes"]


class MapSnapshotAssertion(_Assertion):
    kind: Literal["map_snapshot"]
    map_id: StableId


class MapDeltaAssertion(_Assertion):
    kind: Literal["map_delta"]
    map_id: StableId


class OrderedEventsAssertion(_Assertion):
    kind: Literal["ordered_events"]
    stream_id: StableId


class CounterAssertion(_Assertion):
    kind: Literal["counter"]
    counter_id: StableId
    mode: Literal["final", "delta"]


XdpAssertion = Annotated[
    RetvalAssertion
    | PacketBytesAssertion
    | ContextBytesAssertion
    | MapSnapshotAssertion
    | MapDeltaAssertion
    | OrderedEventsAssertion
    | CounterAssertion,
    Field(discriminator="kind"),
]


class ByteRange(_OracleModel):
    offset: Annotated[int, Field(ge=0, le=MAX_OBSERVATION_BYTES)]
    length: Annotated[int, Field(ge=1, le=MAX_OBSERVATION_BYTES)]

    @model_validator(mode="after")
    def end_must_fit_global_bound(self) -> Self:
        if self.offset + self.length > MAX_OBSERVATION_BYTES:
            raise ValueError("normalization byte range exceeds the observation bound")
        return self


class MaskByteRanges(_OracleModel):
    """Replace declared byte ranges with zeroes before one assertion is compared."""

    kind: Literal["mask_byte_ranges"]
    normalization_id: StableId
    assertion_id: StableId
    component: Literal["bytes", "key", "value", "record"]
    ranges: Annotated[tuple[ByteRange, ...], Field(min_length=1, max_length=256)]

    @model_validator(mode="after")
    def ranges_are_canonical_and_disjoint(self) -> Self:
        positions = [(item.offset, item.offset + item.length) for item in self.ranges]
        if positions != sorted(positions):
            raise ValueError("normalization byte ranges must be sorted")
        if any(
            left_end > right_start
            for (_, left_end), (right_start, _) in pairwise(positions)
        ):
            raise ValueError("normalization byte ranges must not overlap")
        return self


NormalizationRule = Annotated[MaskByteRanges, Field(discriminator="kind")]


class XdpOracleCase(_OracleModel):
    case_id: StableId
    input: XdpCaseInput
    assertions: Annotated[
        tuple[XdpAssertion, ...],
        Field(min_length=1, max_length=MAX_ASSERTIONS_PER_CASE),
    ]
    normalizations: Annotated[
        tuple[NormalizationRule, ...],
        Field(max_length=MAX_NORMALIZATIONS_PER_CASE),
    ] = ()

    @model_validator(mode="after")
    def declarations_are_closed_and_unambiguous(self) -> Self:
        assertion_by_id = {item.assertion_id: item for item in self.assertions}
        if len(assertion_by_id) != len(self.assertions):
            raise ValueError("oracle assertion IDs must be unique within a case")
        if not any(item.required for item in self.assertions):
            raise ValueError("each oracle case requires at least one required assertion")

        targets: list[tuple[str, ...]] = []
        for assertion in self.assertions:
            target: tuple[str, ...]
            if isinstance(assertion, (MapSnapshotAssertion, MapDeltaAssertion)):
                target = (assertion.kind, assertion.map_id)
            elif isinstance(assertion, OrderedEventsAssertion):
                target = (assertion.kind, assertion.stream_id)
            elif isinstance(assertion, CounterAssertion):
                target = (assertion.kind, assertion.counter_id, assertion.mode)
            else:
                target = (assertion.kind,)
            targets.append(target)
        if len(targets) != len(set(targets)):
            raise ValueError("oracle assertion targets must be unique within a case")

        normalization_ids = [item.normalization_id for item in self.normalizations]
        if len(normalization_ids) != len(set(normalization_ids)):
            raise ValueError("normalization IDs must be unique within a case")
        if normalization_ids != sorted(normalization_ids):
            raise ValueError("normalization rules must be sorted by normalization ID")

        occupied: dict[tuple[str, str], list[tuple[int, int]]] = {}
        for rule in self.normalizations:
            target_assertion = assertion_by_id.get(rule.assertion_id)
            if target_assertion is None:
                raise ValueError("normalization targets an undeclared assertion")
            allowed_components: set[str]
            if isinstance(target_assertion, (PacketBytesAssertion, ContextBytesAssertion)):
                allowed_components = {"bytes"}
            elif isinstance(target_assertion, (MapSnapshotAssertion, MapDeltaAssertion)):
                allowed_components = {"key", "value"}
            elif isinstance(target_assertion, OrderedEventsAssertion):
                allowed_components = {"record"}
            else:
                allowed_components = set()
            if rule.component not in allowed_components:
                raise ValueError("normalization component is incompatible with assertion kind")

            slot = occupied.setdefault((rule.assertion_id, rule.component), [])
            for byte_range in rule.ranges:
                slot.append(
                    (byte_range.offset, byte_range.offset + byte_range.length)
                )

        for slot in occupied.values():
            slot.sort()
            if any(
                left_end > right_start
                for (_, left_end), (right_start, _) in pairwise(slot)
            ):
                raise ValueError("normalization rules overlap for one assertion component")
        return self


class XdpOracleContract(_OracleModel):
    """Frozen comparison logic and input identities for one evaluation plan."""

    schema_version: Literal["bpe.xdp-oracle-contract.v1"]
    profile: Literal["xdp-differential-oracle-v1"]
    task_id: StableId
    task_version: StableId
    task_bundle_sha256: Sha256
    evaluation_plan_sha256: Sha256
    grader_id: Sha256
    environment_id: StableId
    environment_sha256: Sha256
    harness_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    normalizer_version: StableId
    normalizer_sha256: Sha256
    reference_program: ContentIdentity
    cases: Annotated[tuple[XdpOracleCase, ...], Field(min_length=1, max_length=MAX_ORACLE_CASES)]

    @model_validator(mode="after")
    def case_ids_are_unique(self) -> Self:
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("oracle case IDs must be unique")
        return self


class MapEntry(_OracleModel):
    key: NonEmptyHexBytes
    value: NonEmptyHexBytes


class MapStateTrace(_OracleModel):
    map_id: StableId
    before: Annotated[tuple[MapEntry, ...], Field(max_length=MAX_COLLECTION_ITEMS)]
    after: Annotated[tuple[MapEntry, ...], Field(max_length=MAX_COLLECTION_ITEMS)]

    @model_validator(mode="after")
    def entries_are_sorted_and_unique(self) -> Self:
        for label, entries in (("before", self.before), ("after", self.after)):
            keys = [entry.key for entry in entries]
            if keys != sorted(keys):
                raise ValueError(f"map {label} entries must be sorted by key bytes")
            if len(keys) != len(set(keys)):
                raise ValueError(f"map {label} keys must be unique")
        return self


class EventStreamTrace(_OracleModel):
    stream_id: StableId
    records: Annotated[tuple[NonEmptyHexBytes, ...], Field(max_length=MAX_COLLECTION_ITEMS)]


class CounterTrace(_OracleModel):
    counter_id: StableId
    before: Unsigned64
    after: Unsigned64


class XdpRawObservation(_OracleModel):
    """Unnormalized outputs from one fresh-object, repeat-one execution."""

    retval: Unsigned32
    packet_bytes: HexBytes | None
    context_bytes: HexBytes | None
    maps: Annotated[tuple[MapStateTrace, ...], Field(max_length=MAX_COLLECTION_ITEMS)] = ()
    events: Annotated[tuple[EventStreamTrace, ...], Field(max_length=MAX_COLLECTION_ITEMS)] = ()
    counters: Annotated[tuple[CounterTrace, ...], Field(max_length=MAX_COLLECTION_ITEMS)] = ()

    @model_validator(mode="after")
    def named_collections_are_sorted_and_unique(self) -> Self:
        for label, identifiers in (
            ("map", [item.map_id for item in self.maps]),
            ("event stream", [item.stream_id for item in self.events]),
            ("counter", [item.counter_id for item in self.counters]),
        ):
            if identifiers != sorted(identifiers):
                raise ValueError(f"{label} traces must be sorted by identifier")
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"{label} trace identifiers must be unique")
        if self.byte_size() > MAX_OBSERVATION_BYTES:
            raise ValueError("raw observation exceeds the aggregate byte bound")
        return self

    def byte_size(self) -> int:
        """Return the exact number of decoded bytes represented by this observation."""

        total = sum(
            len(value) // 2
            for value in (self.packet_bytes, self.context_bytes)
            if value is not None
        )
        total += sum(
            (len(entry.key) + len(entry.value)) // 2
            for state in self.maps
            for entries in (state.before, state.after)
            for entry in entries
        )
        total += sum(
            len(record) // 2 for stream in self.events for record in stream.records
        )
        return total


class XdpCaseTrace(_OracleModel):
    case_id: StableId
    input: XdpCaseInput
    observation: XdpRawObservation


class XdpTrace(_OracleModel):
    """A content-addressable raw trace emitted by a future trusted runner."""

    schema_version: Literal["bpe.xdp-trace.v1"]
    profile: Literal["xdp-bpf-prog-test-run-trace-v1"]
    role: Literal["candidate", "reference"]
    task_id: StableId
    task_version: StableId
    task_bundle_sha256: Sha256
    evaluation_plan_sha256: Sha256
    grader_id: Sha256
    environment_id: StableId
    environment_sha256: Sha256
    harness_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    program: ContentIdentity
    cases: Annotated[tuple[XdpCaseTrace, ...], Field(min_length=1, max_length=MAX_ORACLE_CASES)]

    @model_validator(mode="after")
    def case_ids_are_unique(self) -> Self:
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("trace case IDs must be unique")
        if sum(case.observation.byte_size() for case in self.cases) > MAX_TRACE_OBSERVATION_BYTES:
            raise ValueError("trace exceeds the aggregate observation byte bound")
        return self


class RetvalObservation(_OracleModel):
    kind: Literal["retval"]
    assertion_id: StableId
    value: Unsigned32


class PacketBytesObservation(_OracleModel):
    kind: Literal["packet_bytes"]
    assertion_id: StableId
    value: HexBytes


class ContextBytesObservation(_OracleModel):
    kind: Literal["context_bytes"]
    assertion_id: StableId
    value: HexBytes


class MapSnapshotObservation(_OracleModel):
    kind: Literal["map_snapshot"]
    assertion_id: StableId
    map_id: StableId
    entries: Annotated[tuple[MapEntry, ...], Field(max_length=MAX_COLLECTION_ITEMS)]

    @model_validator(mode="after")
    def entries_are_sorted_and_unique(self) -> Self:
        keys = [entry.key for entry in self.entries]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValueError("normalized map entries must be sorted and unique")
        return self


class MapChange(_OracleModel):
    kind: Literal["inserted", "updated", "deleted"]
    key: NonEmptyHexBytes
    before: NonEmptyHexBytes | None
    after: NonEmptyHexBytes | None

    @model_validator(mode="after")
    def values_match_change_kind(self) -> Self:
        if self.kind == "inserted" and (self.before is not None or self.after is None):
            raise ValueError("inserted map changes require only an after value")
        if self.kind == "deleted" and (self.before is None or self.after is not None):
            raise ValueError("deleted map changes require only a before value")
        if self.kind == "updated" and (
            self.before is None or self.after is None or self.before == self.after
        ):
            raise ValueError("updated map changes require two different values")
        return self


class MapDeltaObservation(_OracleModel):
    kind: Literal["map_delta"]
    assertion_id: StableId
    map_id: StableId
    changes: Annotated[tuple[MapChange, ...], Field(max_length=MAX_COLLECTION_ITEMS)]

    @model_validator(mode="after")
    def changes_are_sorted_and_unique(self) -> Self:
        keys = [change.key for change in self.changes]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValueError("map changes must be sorted and unique by key")
        return self


class OrderedEventsObservation(_OracleModel):
    kind: Literal["ordered_events"]
    assertion_id: StableId
    stream_id: StableId
    records: Annotated[tuple[NonEmptyHexBytes, ...], Field(max_length=MAX_COLLECTION_ITEMS)]


class CounterObservation(_OracleModel):
    kind: Literal["counter"]
    assertion_id: StableId
    counter_id: StableId
    mode: Literal["final", "delta"]
    value: CounterDelta


NormalizedAssertionObservation = Annotated[
    RetvalObservation
    | PacketBytesObservation
    | ContextBytesObservation
    | MapSnapshotObservation
    | MapDeltaObservation
    | OrderedEventsObservation
    | CounterObservation,
    Field(discriminator="kind"),
]


class NormalizedObservation(_OracleModel):
    """The exact comparison projection deterministically derived for one case."""

    case_id: StableId
    input: XdpCaseInput
    assertions: Annotated[
        tuple[NormalizedAssertionObservation, ...],
        Field(min_length=1, max_length=MAX_ASSERTIONS_PER_CASE),
    ]
    normalizations_applied: Annotated[
        tuple[StableId, ...],
        Field(max_length=MAX_NORMALIZATIONS_PER_CASE),
    ] = ()

    @model_validator(mode="after")
    def identities_are_unique(self) -> Self:
        assertion_ids = [item.assertion_id for item in self.assertions]
        if len(assertion_ids) != len(set(assertion_ids)):
            raise ValueError("normalized assertion observations must be unique")
        if len(self.normalizations_applied) != len(set(self.normalizations_applied)):
            raise ValueError("applied normalization IDs must be unique")
        if list(self.normalizations_applied) != sorted(self.normalizations_applied):
            raise ValueError("applied normalization IDs must be sorted")
        return self


class AssertionComparison(_OracleModel):
    assertion_id: StableId
    kind: Literal[
        "retval",
        "packet_bytes",
        "context_bytes",
        "map_snapshot",
        "map_delta",
        "ordered_events",
        "counter",
    ]
    required: bool
    weight: Annotated[float, Field(gt=0, le=1_000_000)]
    matched: bool
    expected_sha256: Sha256
    actual_sha256: Sha256


class OracleCaseResult(_OracleModel):
    case_id: StableId
    input: XdpCaseInput
    candidate_observation_sha256: Sha256
    reference_observation_sha256: Sha256
    assertions: Annotated[
        tuple[AssertionComparison, ...],
        Field(min_length=1, max_length=MAX_ASSERTIONS_PER_CASE),
    ]
    passed: bool

    @model_validator(mode="after")
    def pass_flag_matches_required_assertions(self) -> Self:
        expected = all(item.matched for item in self.assertions if item.required)
        if self.passed != expected:
            raise ValueError("case pass flag does not match required assertion results")
        return self


class FirstDivergence(_OracleModel):
    case_index: Annotated[int, Field(ge=0, lt=MAX_ORACLE_CASES)]
    assertion_index: Annotated[int, Field(ge=0, lt=MAX_ASSERTIONS_PER_CASE)]
    case_id: StableId
    assertion_id: StableId
    kind: Literal[
        "retval",
        "packet_bytes",
        "context_bytes",
        "map_snapshot",
        "map_delta",
        "ordered_events",
        "counter",
    ]
    expected_sha256: Sha256
    actual_sha256: Sha256


class OracleReport(_OracleModel):
    """Replayable result of comparing a candidate trace to a reference trace."""

    schema_version: Literal["bpe.oracle-report.v1"]
    contract_sha256: Sha256
    candidate_trace_sha256: Sha256
    reference_trace_sha256: Sha256
    task_id: StableId
    task_version: StableId
    task_bundle_sha256: Sha256
    evaluation_plan_sha256: Sha256
    grader_id: Sha256
    environment_id: StableId
    environment_sha256: Sha256
    harness_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    normalizer_version: StableId
    normalizer_sha256: Sha256
    candidate_program: ContentIdentity
    reference_program: ContentIdentity
    candidate_observations: Annotated[
        tuple[NormalizedObservation, ...],
        Field(min_length=1, max_length=MAX_ORACLE_CASES),
    ]
    reference_observations: Annotated[
        tuple[NormalizedObservation, ...],
        Field(min_length=1, max_length=MAX_ORACLE_CASES),
    ]
    cases: Annotated[
        tuple[OracleCaseResult, ...],
        Field(min_length=1, max_length=MAX_ORACLE_CASES),
    ]
    strict_success: bool
    first_divergence: FirstDivergence | None

    @model_validator(mode="after")
    def derived_fields_are_internally_consistent(self) -> Self:
        if not (
            len(self.candidate_observations)
            == len(self.reference_observations)
            == len(self.cases)
        ):
            raise ValueError("oracle report case collections differ in length")

        expected_first: FirstDivergence | None = None
        for case_index, (candidate, reference, result) in enumerate(
            zip(
                self.candidate_observations,
                self.reference_observations,
                self.cases,
                strict=True,
            )
        ):
            if not (
                candidate.case_id == reference.case_id == result.case_id
                and candidate.input == reference.input == result.input
            ):
                raise ValueError("oracle report case identities or inputs differ")
            if result.candidate_observation_sha256 != sha256_json(candidate):
                raise ValueError("candidate observation digest is inconsistent")
            if result.reference_observation_sha256 != sha256_json(reference):
                raise ValueError("reference observation digest is inconsistent")
            if not (
                len(candidate.assertions)
                == len(reference.assertions)
                == len(result.assertions)
            ):
                raise ValueError("oracle report assertion collections differ in length")
            for assertion_index, (actual, expected, comparison) in enumerate(
                zip(
                    candidate.assertions,
                    reference.assertions,
                    result.assertions,
                    strict=True,
                )
            ):
                if not (
                    actual.assertion_id
                    == expected.assertion_id
                    == comparison.assertion_id
                    and actual.kind == expected.kind == comparison.kind
                ):
                    raise ValueError("oracle report assertion identities or kinds differ")
                actual_sha256 = sha256_json(actual)
                expected_sha256 = sha256_json(expected)
                if (
                    comparison.actual_sha256 != actual_sha256
                    or comparison.expected_sha256 != expected_sha256
                    or comparison.matched != (actual == expected)
                ):
                    raise ValueError("oracle assertion comparison is inconsistent")
                if expected_first is None and comparison.required and not comparison.matched:
                    expected_first = FirstDivergence(
                        case_index=case_index,
                        assertion_index=assertion_index,
                        case_id=result.case_id,
                        assertion_id=comparison.assertion_id,
                        kind=comparison.kind,
                        expected_sha256=expected_sha256,
                        actual_sha256=actual_sha256,
                    )

        expected_success = all(result.passed for result in self.cases)
        if self.strict_success != expected_success:
            raise ValueError("strict-success flag does not match required assertions")
        if self.first_divergence != expected_first:
            raise ValueError("first divergence is not the first required mismatch")
        return self


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _revalidate(model_type: type[_ModelT], value: _ModelT) -> _ModelT:
    """Defeat unsafe Pydantic construction before a record reaches the oracle."""

    return model_type.model_validate(value.model_dump(mode="python"), strict=True)


def _mask_bytes(value: str, rules: tuple[MaskByteRanges, ...]) -> str:
    data = bytearray.fromhex(value)
    for rule in rules:
        for byte_range in rule.ranges:
            end = byte_range.offset + byte_range.length
            if end > len(data):
                raise OracleContractError(
                    f"normalization {rule.normalization_id!r} exceeds observed bytes"
                )
            data[byte_range.offset:end] = b"\x00" * byte_range.length
    return data.hex()


def _rules_for(
    case: XdpOracleCase,
    assertion_id: str,
    component: str,
) -> tuple[MaskByteRanges, ...]:
    return tuple(
        rule
        for rule in case.normalizations
        if rule.assertion_id == assertion_id and rule.component == component
    )


def _normalized_entries(
    entries: tuple[MapEntry, ...],
    *,
    key_rules: tuple[MaskByteRanges, ...],
    value_rules: tuple[MaskByteRanges, ...],
) -> tuple[MapEntry, ...]:
    normalized = tuple(
        MapEntry(
            key=_mask_bytes(entry.key, key_rules),
            value=_mask_bytes(entry.value, value_rules),
        )
        for entry in entries
    )
    ordered = tuple(sorted(normalized, key=lambda item: item.key))
    keys = [entry.key for entry in ordered]
    if len(keys) != len(set(keys)):
        raise OracleContractError("normalization collapses distinct map keys")
    return ordered


def _map_delta(
    before: tuple[MapEntry, ...],
    after: tuple[MapEntry, ...],
) -> tuple[MapChange, ...]:
    before_by_key = {entry.key: entry.value for entry in before}
    after_by_key = {entry.key: entry.value for entry in after}
    changes: list[MapChange] = []
    for key in sorted(before_by_key.keys() | after_by_key.keys()):
        old = before_by_key.get(key)
        new = after_by_key.get(key)
        if old is None:
            changes.append(MapChange(kind="inserted", key=key, before=None, after=new))
        elif new is None:
            changes.append(MapChange(kind="deleted", key=key, before=old, after=None))
        elif old != new:
            changes.append(MapChange(kind="updated", key=key, before=old, after=new))
    return tuple(changes)


def _expected_named_components(
    case: XdpOracleCase,
) -> tuple[set[str], set[str], set[str]]:
    maps = {
        assertion.map_id
        for assertion in case.assertions
        if isinstance(assertion, (MapSnapshotAssertion, MapDeltaAssertion))
    }
    streams = {
        assertion.stream_id
        for assertion in case.assertions
        if isinstance(assertion, OrderedEventsAssertion)
    }
    counters = {
        assertion.counter_id
        for assertion in case.assertions
        if isinstance(assertion, CounterAssertion)
    }
    return maps, streams, counters


def _validate_observation_shape(case: XdpOracleCase, trace: XdpCaseTrace) -> None:
    observation = trace.observation
    expects_packet = any(isinstance(item, PacketBytesAssertion) for item in case.assertions)
    expects_context = any(isinstance(item, ContextBytesAssertion) for item in case.assertions)
    if (observation.packet_bytes is not None) != expects_packet:
        raise OracleContractError("packet observation presence does not match the contract")
    if (observation.context_bytes is not None) != expects_context:
        raise OracleContractError("context observation presence does not match the contract")

    expected_maps, expected_streams, expected_counters = _expected_named_components(case)
    if {item.map_id for item in observation.maps} != expected_maps:
        raise OracleContractError("map observations do not exactly match declared assertions")
    if {item.stream_id for item in observation.events} != expected_streams:
        raise OracleContractError("event observations do not exactly match declared assertions")
    if {item.counter_id for item in observation.counters} != expected_counters:
        raise OracleContractError("counter observations do not exactly match declared assertions")


def _normalize_case(case: XdpOracleCase, trace: XdpCaseTrace) -> NormalizedObservation:
    _validate_observation_shape(case, trace)
    raw = trace.observation
    maps = {item.map_id: item for item in raw.maps}
    events = {item.stream_id: item for item in raw.events}
    counters = {item.counter_id: item for item in raw.counters}
    observations: list[NormalizedAssertionObservation] = []

    for assertion in case.assertions:
        assertion_id = assertion.assertion_id
        if isinstance(assertion, RetvalAssertion):
            observations.append(
                RetvalObservation(kind="retval", assertion_id=assertion_id, value=raw.retval)
            )
        elif isinstance(assertion, PacketBytesAssertion):
            if raw.packet_bytes is None:  # guarded above; keeps type narrowing explicit
                raise OracleContractError("packet bytes are missing")
            observations.append(
                PacketBytesObservation(
                    kind="packet_bytes",
                    assertion_id=assertion_id,
                    value=_mask_bytes(
                        raw.packet_bytes,
                        _rules_for(case, assertion_id, "bytes"),
                    ),
                )
            )
        elif isinstance(assertion, ContextBytesAssertion):
            if raw.context_bytes is None:
                raise OracleContractError("context bytes are missing")
            observations.append(
                ContextBytesObservation(
                    kind="context_bytes",
                    assertion_id=assertion_id,
                    value=_mask_bytes(
                        raw.context_bytes,
                        _rules_for(case, assertion_id, "bytes"),
                    ),
                )
            )
        elif isinstance(assertion, (MapSnapshotAssertion, MapDeltaAssertion)):
            state = maps[assertion.map_id]
            key_rules = _rules_for(case, assertion_id, "key")
            value_rules = _rules_for(case, assertion_id, "value")
            before = _normalized_entries(
                state.before,
                key_rules=key_rules,
                value_rules=value_rules,
            )
            after = _normalized_entries(
                state.after,
                key_rules=key_rules,
                value_rules=value_rules,
            )
            if isinstance(assertion, MapSnapshotAssertion):
                observations.append(
                    MapSnapshotObservation(
                        kind="map_snapshot",
                        assertion_id=assertion_id,
                        map_id=assertion.map_id,
                        entries=after,
                    )
                )
            else:
                observations.append(
                    MapDeltaObservation(
                        kind="map_delta",
                        assertion_id=assertion_id,
                        map_id=assertion.map_id,
                        changes=_map_delta(before, after),
                    )
                )
        elif isinstance(assertion, OrderedEventsAssertion):
            stream = events[assertion.stream_id]
            rules = _rules_for(case, assertion_id, "record")
            observations.append(
                OrderedEventsObservation(
                    kind="ordered_events",
                    assertion_id=assertion_id,
                    stream_id=assertion.stream_id,
                    records=tuple(_mask_bytes(record, rules) for record in stream.records),
                )
            )
        else:
            counter = counters[assertion.counter_id]
            value = counter.after if assertion.mode == "final" else counter.after - counter.before
            observations.append(
                CounterObservation(
                    kind="counter",
                    assertion_id=assertion_id,
                    counter_id=assertion.counter_id,
                    mode=assertion.mode,
                    value=value,
                )
            )

    return NormalizedObservation(
        case_id=case.case_id,
        input=case.input,
        assertions=tuple(observations),
        normalizations_applied=tuple(rule.normalization_id for rule in case.normalizations),
    )


def _validate_trace(
    contract: XdpOracleContract,
    trace: XdpTrace,
    *,
    role: Literal["candidate", "reference"],
) -> None:
    if trace.role != role:
        raise OracleContractError(f"expected a {role} trace")
    contract_identity = (
        contract.task_id,
        contract.task_version,
        contract.task_bundle_sha256,
        contract.evaluation_plan_sha256,
        contract.grader_id,
        contract.environment_id,
        contract.environment_sha256,
        contract.harness_commit,
    )
    trace_identity = (
        trace.task_id,
        trace.task_version,
        trace.task_bundle_sha256,
        trace.evaluation_plan_sha256,
        trace.grader_id,
        trace.environment_id,
        trace.environment_sha256,
        trace.harness_commit,
    )
    if trace_identity != contract_identity:
        raise OracleContractError(f"{role} trace identity does not match the oracle contract")
    if role == "reference" and trace.program != contract.reference_program:
        raise OracleContractError("reference trace does not use the contracted reference program")
    if len(trace.cases) != len(contract.cases):
        raise OracleContractError(f"{role} trace has missing or extra cases")
    for expected, observed in zip(contract.cases, trace.cases, strict=True):
        if observed.case_id != expected.case_id:
            raise OracleContractError(f"{role} trace case order or identity differs")
        if observed.input != expected.input:
            raise OracleContractError(f"{role} trace input identity differs")
        _validate_observation_shape(expected, observed)


def derive_oracle_report(
    contract: XdpOracleContract,
    candidate_trace: XdpTrace,
    reference_trace: XdpTrace,
) -> OracleReport:
    """Deterministically compare two raw traces under a closed oracle contract."""

    contract = _revalidate(XdpOracleContract, contract)
    candidate_trace = _revalidate(XdpTrace, candidate_trace)
    reference_trace = _revalidate(XdpTrace, reference_trace)
    _validate_trace(contract, candidate_trace, role="candidate")
    _validate_trace(contract, reference_trace, role="reference")

    candidate_observations = tuple(
        _normalize_case(case, trace)
        for case, trace in zip(contract.cases, candidate_trace.cases, strict=True)
    )
    reference_observations = tuple(
        _normalize_case(case, trace)
        for case, trace in zip(contract.cases, reference_trace.cases, strict=True)
    )
    case_results: list[OracleCaseResult] = []
    first_divergence: FirstDivergence | None = None

    for case_index, (case, actual, expected) in enumerate(
        zip(contract.cases, candidate_observations, reference_observations, strict=True)
    ):
        comparisons: list[AssertionComparison] = []
        for assertion_index, (declaration, actual_value, expected_value) in enumerate(
            zip(case.assertions, actual.assertions, expected.assertions, strict=True)
        ):
            actual_sha256 = sha256_json(actual_value)
            expected_sha256 = sha256_json(expected_value)
            matched = actual_value == expected_value
            comparison = AssertionComparison(
                assertion_id=declaration.assertion_id,
                kind=declaration.kind,
                required=declaration.required,
                weight=declaration.weight,
                matched=matched,
                expected_sha256=expected_sha256,
                actual_sha256=actual_sha256,
            )
            comparisons.append(comparison)
            if first_divergence is None and declaration.required and not matched:
                first_divergence = FirstDivergence(
                    case_index=case_index,
                    assertion_index=assertion_index,
                    case_id=case.case_id,
                    assertion_id=declaration.assertion_id,
                    kind=declaration.kind,
                    expected_sha256=expected_sha256,
                    actual_sha256=actual_sha256,
                )

        case_results.append(
            OracleCaseResult(
                case_id=case.case_id,
                input=case.input,
                candidate_observation_sha256=sha256_json(actual),
                reference_observation_sha256=sha256_json(expected),
                assertions=tuple(comparisons),
                passed=all(item.matched for item in comparisons if item.required),
            )
        )

    return OracleReport(
        schema_version="bpe.oracle-report.v1",
        contract_sha256=sha256_json(contract),
        candidate_trace_sha256=sha256_json(candidate_trace),
        reference_trace_sha256=sha256_json(reference_trace),
        task_id=contract.task_id,
        task_version=contract.task_version,
        task_bundle_sha256=contract.task_bundle_sha256,
        evaluation_plan_sha256=contract.evaluation_plan_sha256,
        grader_id=contract.grader_id,
        environment_id=contract.environment_id,
        environment_sha256=contract.environment_sha256,
        harness_commit=contract.harness_commit,
        normalizer_version=contract.normalizer_version,
        normalizer_sha256=contract.normalizer_sha256,
        candidate_program=candidate_trace.program,
        reference_program=reference_trace.program,
        candidate_observations=candidate_observations,
        reference_observations=reference_observations,
        cases=tuple(case_results),
        strict_success=all(case.passed for case in case_results),
        first_divergence=first_divergence,
    )


def verify_oracle_report(
    contract: XdpOracleContract,
    candidate_trace: XdpTrace,
    reference_trace: XdpTrace,
    report: OracleReport,
) -> OracleReport:
    """Reject any report that is not the exact deterministic derivation."""

    report = _revalidate(OracleReport, report)
    derived = derive_oracle_report(contract, candidate_trace, reference_trace)
    if report != derived:
        raise OracleContractError("oracle report is not the deterministic derivation")
    return report


JSON_SCHEMAS: dict[str, type[BaseModel]] = {
    "xdp-oracle-contract-v1.json": XdpOracleContract,
    "xdp-trace-v1.json": XdpTrace,
    "oracle-report-v1.json": OracleReport,
}


__all__ = [
    "JSON_SCHEMAS",
    "AssertionComparison",
    "ByteRange",
    "ContentIdentity",
    "ContextBytesAssertion",
    "CounterAssertion",
    "CounterTrace",
    "EventStreamTrace",
    "FirstDivergence",
    "MapDeltaAssertion",
    "MapEntry",
    "MapSnapshotAssertion",
    "MapStateTrace",
    "MaskByteRanges",
    "NormalizedObservation",
    "OracleCaseResult",
    "OracleContractError",
    "OracleReport",
    "OrderedEventsAssertion",
    "PacketBytesAssertion",
    "RetvalAssertion",
    "XdpCaseInput",
    "XdpCaseTrace",
    "XdpOracleCase",
    "XdpOracleContract",
    "XdpRawObservation",
    "XdpTrace",
    "derive_oracle_report",
    "verify_oracle_report",
]
