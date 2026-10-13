"""Shared facts every rule in one detection run can rely on."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from moesoc.core.detection import RuleMetadata
from moesoc.core.domains import DomainAlias, DomainMap
from moesoc.core.event import NormalizedEvent


@dataclass(frozen=True, slots=True)
class DetectionContext:
    """Built once per run so every rule matches accounts the same way."""

    domains: DomainMap
    # Every loaded rule, so one rule can avoid re-reporting what another already does.
    rules: Mapping[str, RuleMetadata] = field(default_factory=dict)

    @classmethod
    def from_events(
        cls,
        events: Iterable[NormalizedEvent],
        known_aliases: Iterable[DomainAlias] = (),
        rules: Mapping[str, RuleMetadata] | None = None,
        standalone_hosts: Iterable[str] = (),
    ) -> DetectionContext:
        domains = DomainMap.from_events(
            events, seed=known_aliases, standalone_hosts=standalone_hosts
        )
        return cls(domains=domains, rules=rules or {})


def domains_of(context: DetectionContext | None) -> DomainMap | None:
    return context.domains if context is not None else None
