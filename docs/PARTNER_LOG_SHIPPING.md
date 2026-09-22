# Shipping a partner node's logs to the federation

Every partner node ships its logs to the federation's log server. This is part
of running a node, not an add-on. It lets us diagnose a problem on your node
while it is happening, instead of asking you for files after the fact.

Nothing else about the node changes, and consensus does not depend on this
working.

Logs are kept for 14 days, and entries older than one week are refused on
arrival, so the first run uploads at most the last seven days.

The credential you are given today is the shared agent credential, the same one
the federation's own nodes use. Treat it as sensitive: it is not scoped to your
node, and it is not currently limited to writing. A per-operator, write-only
credential is planned, and when it is issued you will be asked to swap to it.

## What gets sent

Everything the node already writes to disk under its log directory, one file per
level: `info.log`, `error.log`, `debug.log` and `access.log`. Plus the node
container's own stdout and stderr, which is where crash output lands.

`access.log` records HTTP requests to the node's API, including client IP
addresses. If that is a concern, drop the `access` file from the path in
`promtail.yml` before starting.

Nothing else on the host is read. The agent only sees the paths mounted into it.

## The settings

The agent reads these from `promtail.env`, which you create in the next section.
The hostname is fixed for everyone. Your node label and your password are
issued to you: the label comes with this document, the password reaches you on
a separate channel and is never written down here.

```bash
LOKI_URL=logs.theailab.org
NODE_LABEL=            # the label issued to you, e.g. your organisation name
LOKI_PASSWORD=         # sent separately, paste it here
```

`LOKI_URL` is the hostname only, with no scheme and no path. The agent builds
the full address itself.

`NODE_LABEL` is how your node is identified in the dashboard. Use exactly the
label you were issued. Changing it makes your logs land under a name nobody is
looking at, which is the same as not sending them.

The username is always `promtail` and is already set in the agent's config, so
there is nothing to fill in for it.

## Setup

One container, next to the node. From the repository you already have:

```bash
cd tip-protocol/infra/observability/agent
cp promtail.env.example promtail.env
```

Put the settings from the previous section into `promtail.env`, including the
password once it reaches you. Then check one line in
`docker-compose.promtail.yml`. It mounts the host side of the node's log
directory:

```yaml
- ../../../logs/node-1:/tip-logs:ro
```

That path must match what your node writes. It is the host directory your node's
compose file mounts at `/app/node/logs`, which follows `TIP_LOG_DIR` in your
`.env`. If your node uses a different name, change `node-1` to match.

Then start it:

```bash
docker compose -f docker-compose.promtail.yml up -d
docker logs tip-promtail --tail 20
```

A working agent logs nothing alarming and goes quiet. Errors mentioning `401`
mean the password is wrong; errors mentioning `too far behind` mean it is
reading entries older than a week, which is expected on the first run and stops
on its own.

## Confirming it works

Tell us once it is running and we will confirm the logs are arriving, usually
within a minute. From your side, the agent's own log is the only signal:

```bash
docker logs tip-promtail --since 5m | grep -i error
```

Silence is success.

## Stopping it temporarily

```bash
docker compose -f docker-compose.promtail.yml down
```

The node is unaffected. Tell us if you need to stop it for more than a short
maintenance window, so we know the gap in the logs is expected.

## Notes

- The agent reads files only. It never reads your database, your keys or your
  environment file.
- The first run pushes several gigabytes if the node has been busy, because a
  single day of debug output can exceed 80 MB. The server accepts 8 MB per
  second, so expect the backlog to take a while to drain.
- Log files are rotated into dated folders by the node and pruned after 14 days.
  The agent follows the rotation on its own.
- If the node is rebuilt, the agent keeps its position in a named volume, so it
  resumes rather than re-sending everything.
