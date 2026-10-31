"""Runs collectors against targets. Used identically by the CLI and the
local API that backs the desktop app."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception

from .collectors import Collector, CollectorContext, registry
from .config import Settings
from .models import CollectionStatus, CollectorResult, Entity, EntityRef, EntityType, utcnow
from .net import FetchError, RateLimiter, UnsafeTargetError, make_client
from .storage import Store

log = logging.getLogger(__name__)

# Collectors run on entities discovered from a domain seed when expansion is
# on. Limited to IPs: that adds network ownership and ASN context, which is
# what analysts nearly always want next, without fanning out across every
# subdomain and nameserver.
EXPANSION = {EntityType.DOMAIN: {EntityType.IP: ("reverse_dns", "asn", "rdap")}}


class EngineError(Exception):
    pass


@dataclass
class RunOptions:
    collectors: list[str] | None = None  # None = every applicable collector
    direct: bool = False
    expand: bool = False

    def as_dict(self) -> dict:
        return {"collectors": self.collectors, "direct": self.direct, "expand": self.expand}


@dataclass
class RunEvent:
    kind: str  # "started" | "finished"
    collector: str
    target: EntityRef
    result: CollectorResult | None = None


@dataclass
class RunReport:
    run_id: str | None
    target: EntityRef
    status: str
    results: list[CollectorResult] = field(default_factory=list)

    @property
    def failed(self) -> list[CollectorResult]:
        return [r for r in self.results
                if r.status in (CollectionStatus.ERROR, CollectionStatus.TIMEOUT)]


def build_resolver(settings: Settings) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver(configure=not settings.dns.nameservers)
    if settings.dns.nameservers:
        resolver.nameservers = list(settings.dns.nameservers)
    resolver.lifetime = min(settings.network.timeout, 15.0)
    return resolver


class Engine:
    def __init__(self, settings: Settings, store: Store | None = None,
                 collectors: dict[str, Collector] | None = None):
        self.settings = settings
        self.store = store
        self.collectors = collectors if collectors is not None else registry(settings)

    def select(self, target: EntityRef, options: RunOptions) -> list[Collector]:
        if options.collectors:
            unknown = [n for n in options.collectors if n not in self.collectors]
            if unknown:
                raise EngineError(f"unknown collector(s): {', '.join(unknown)}. "
                                  "Run 'strxeye collectors' to list them.")
            chosen = [self.collectors[n] for n in options.collectors]
            unsupported = [c.name for c in chosen if not c.supports(target)]
            if unsupported:
                raise EngineError(f"{', '.join(unsupported)} cannot handle {target.type} targets")
        else:
            chosen = [c for c in self.collectors.values() if c.supports(target)]
        direct_allowed = options.direct or self.settings.collection.allow_direct
        if not direct_allowed:
            explicit_direct = [c.name for c in chosen if c.direct and options.collectors]
            if explicit_direct:
                raise EngineError(
                    f"{', '.join(explicit_direct)} contact the target directly; "
                    "pass --direct (or enable collection.allow_direct) to run them")
            chosen = [c for c in chosen if not c.direct]
        return chosen

    async def run(
        self,
        target: EntityRef,
        options: RunOptions | None = None,
        *,
        investigation_id: str | None = None,
        on_event: Callable[[RunEvent], None] | None = None,
        cancel: asyncio.Event | None = None,
        run_id: str | None = None,
    ) -> RunReport:
        """Collect on ``target``. With ``investigation_id`` results are saved
        as they arrive, so a cancelled or crashed run keeps what it got.
        ``run_id`` lets a caller that already created the run row (the API,
        which must return the ID before collection finishes) pass it in."""
        options = options or RunOptions()
        chosen = self.select(target, options)
        if not chosen:
            raise EngineError(f"no collectors support {target.type} targets yet")

        if investigation_id:
            if self.store is None:
                raise EngineError("an investigation run needs a store")
            if run_id is None:
                run_id = self.prepare_run(investigation_id, target, options)

        report = RunReport(run_id=run_id, target=target, status="running")
        cancel = cancel or asyncio.Event()
        try:
            async with make_client(self.settings.network) as client:
                ctx = CollectorContext(settings=self.settings, client=client,
                                       limiter=RateLimiter(0.2),
                                       resolver=build_resolver(self.settings))
                await self._run_batch(ctx, [(c, target) for c in chosen], report,
                                      investigation_id, on_event, cancel)
                if options.expand and not cancel.is_set():
                    jobs = self._expansion_jobs(target, report, options)
                    await self._run_batch(ctx, jobs, report, investigation_id, on_event, cancel)
            report.status = "cancelled" if cancel.is_set() else "completed"
        except (asyncio.CancelledError, KeyboardInterrupt):
            report.status = "cancelled"
            raise
        except BaseException:
            report.status = "failed"
            raise
        finally:
            if run_id and self.store:
                self.store.finish_run(run_id, report.status)
        return report

    def prepare_run(self, investigation_id: str, target: EntityRef, options: RunOptions) -> str:
        assert self.store is not None
        self.store.add_seed(investigation_id, target)
        return self.store.start_run(investigation_id, target, options.as_dict())

    def _expansion_jobs(self, seed: EntityRef, report: RunReport,
                        options: RunOptions) -> list[tuple[Collector, EntityRef]]:
        plan = EXPANSION.get(seed.type, {})
        discovered: list[EntityRef] = []
        for result in report.results:
            for entity in result.entities:
                if entity.type in plan and entity.ref not in discovered and entity.ref != seed:
                    discovered.append(entity.ref)
        limit = self.settings.collection.max_expansions
        jobs = []
        for ref in discovered[:limit]:
            for name in plan[ref.type]:
                if name in self.collectors:
                    jobs.append((self.collectors[name], ref))
        return jobs

    async def _run_batch(self, ctx, jobs, report, investigation_id, on_event, cancel) -> None:
        # Bounded concurrency: enough to overlap slow sources, low enough to
        # stay polite to public services during expansion.
        semaphore = asyncio.Semaphore(6)

        async def one(collector: Collector, target: EntityRef) -> None:
            async with semaphore:
                if cancel.is_set():
                    return
                if on_event:
                    on_event(RunEvent("started", collector.name, target))
                result = await self._run_collector(collector, target, ctx, cancel)
                report.results.append(result)
                if investigation_id and self.store:
                    self.store.save_result(investigation_id, report.run_id, result)
                if on_event:
                    on_event(RunEvent("finished", collector.name, target, result))

        await asyncio.gather(*(one(c, t) for c, t in jobs))

    async def _run_collector(self, collector: Collector, target: EntityRef,
                             ctx: CollectorContext, cancel: asyncio.Event) -> CollectorResult:
        started = utcnow()
        timeout = self.settings.collection.collector_timeout
        task = asyncio.create_task(collector.collect(target, ctx))
        cancel_wait = asyncio.create_task(cancel.wait())
        status, error, findings = CollectionStatus.ERROR, None, None
        try:
            done, _ = await asyncio.wait({task, cancel_wait}, timeout=timeout,
                                         return_when=asyncio.FIRST_COMPLETED)
            if task in done:
                findings = task.result()
                status = findings.status
            elif cancel_wait in done:
                status, error = CollectionStatus.CANCELLED, "cancelled by user"
            else:
                status, error = CollectionStatus.TIMEOUT, f"no result within {timeout:.0f}s"
        except (FetchError, UnsafeTargetError) as exc:
            error = str(exc)
        except dns.exception.Timeout:
            status, error = CollectionStatus.TIMEOUT, "DNS query timed out"
        except dns.exception.DNSException as exc:
            error = f"DNS error: {exc}"
        except Exception as exc:  # noqa: BLE001 - a buggy collector must not end the run
            log.exception("collector %s crashed on %s", collector.name, target)
            error = f"internal error in collector: {exc.__class__.__name__}: {exc}"
        finally:
            for t in (task, cancel_wait):
                if not t.done():
                    t.cancel()
            await asyncio.gather(task, cancel_wait, return_exceptions=True)

        result = CollectorResult(collector=collector.name, target=target, status=status,
                                 started_at=started, finished_at=utcnow(), error=error)
        if findings is not None:
            result.entities = list(findings.entities.values())
            result.observations = findings.observations
            result.relationships = findings.relationships
            result.evidence = list(findings.evidence.values())
            result.notes = findings.notes
            # Make sure the target itself is stored even if the collector
            # only produced observations about it.
            if target not in findings.entities:
                result.entities.insert(0, Entity(type=target.type, value=target.value))
        return result
