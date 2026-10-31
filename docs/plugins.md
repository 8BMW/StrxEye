# Writing a collector plugin

A plugin is a normal Python package that exposes a `Collector` subclass through
the `strxeye.collectors` entry point group.

## Minimal example

`pyproject.toml`:

```toml
[project]
name = "strxeye-example-plugin"
version = "0.1.0"
dependencies = ["strxeye>=0.1"]

[project.entry-points."strxeye.collectors"]
securitytxt = "strxeye_example_plugin:SecurityTxtCollector"
```

`strxeye_example_plugin.py`:

```python
from strxeye.collectors.base import Collector, CollectorContext, Findings
from strxeye.models import EntityRef, EntityType
from strxeye.net import ensure_public_host, fetch


class SecurityTxtCollector(Collector):
    name = "securitytxt"
    title = "security.txt"
    description = "Reads /.well-known/security.txt from the site."
    version = "0.1.0"
    sdk_version = 1
    accepts = frozenset({EntityType.DOMAIN})
    direct = True  # it connects to the target

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        await ensure_public_host(target.value)
        url = f"https://{target.value}/.well-known/security.txt"
        response = await fetch(ctx.client, url, limiter=ctx.limiter, allow_statuses=(404,))
        if response.status_code == 404:
            return found  # recorded as no_data
        evidence = found.add_evidence(url, response.text)
        for line in response.text.splitlines():
            if line.lower().startswith("contact:"):
                found.observe(target, "securitytxt.contact", line.split(":", 1)[1].strip(),
                              method="HTTPS GET", evidence_id=evidence, source_url=url)
        return found
```

## Rules

- Return a `Findings` object; never return made-up values. Raise
  `strxeye.net.FetchError` (or let it propagate from `fetch`) for source
  failures; the engine records them per collector.
- Store the raw response with `add_evidence` and pass its ID to observations
  and relationships.
- Set `direct = True` if the collector connects to anything the target
  controls, and call `ensure_public_host` before connecting.
- List third-party services you contact in `sources` so users know where their
  queries go.
- Use `ctx.client` and `ctx.limiter` rather than creating your own clients, so
  timeouts, the user agent and rate limits apply.
- Set `sdk_version = 1`. Plugins built for another SDK version are skipped with
  a warning.

## Installing and trusting

```bash
pip install ./strxeye-example-plugin
strxeye plugins list                 # shows it as untrusted; nothing is imported yet
strxeye plugins trust securitytxt    # shows a warning and asks for confirmation
strxeye collectors                   # now includes "securitytxt"
```

Trust is stored as `name==version` in the config file. Upgrading the plugin
makes it untrusted again until you re-run `trust`. `strxeye plugins untrust
NAME` removes it.

Plugins run as normal Python code with your user's permissions. Only trust
code you have reviewed or whose author you trust.
