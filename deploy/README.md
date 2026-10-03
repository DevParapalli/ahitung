# Deploying ahitung

ahitung runs as rootless Podman containers managed by systemd through
Quadlet. One target starts and stops the whole stack:

```
scripts/install          # once, and after adding or renaming a unit
scripts/rebuild egressd  # build the image
scripts/up               # systemctl --user start ahitung.target
scripts/status
scripts/down
```

The stack currently holds `egressd` and its three networks.

## What `scripts/install` touches

Everything outside the repository that the stack uses. It prints each path,
and re-running it changes nothing that already exists.

| Path | What |
|---|---|
| `~/.config/containers/systemd/ahitung` | Symlink to `deploy/quadlet/`. Quadlet generates one systemd service per file in it. |
| `~/.config/systemd/user/ahitung.target` | Copy of `deploy/ahitung.target`. |
| `~/.config/ahitung/egressd.json` | The live egress policy, seeded from `deploy/egressd.example.json` only if absent. Yours to edit; never overwritten. |

`~` stands for `$XDG_CONFIG_HOME` when it is set.

User services stop when you log out unless lingering is enabled. `install`
prints the command if it is not; it does not run it.

Unit edits in `deploy/quadlet/` take effect after
`systemctl --user daemon-reload` and a restart of the unit.

## Networks

| Network | Subnet | Internet | Who |
|---|---|---|---|
| `ahitung-sandbox` | 10.89.0.0/24 | no | the workspace; egressd at 10.89.0.2 |
| `ahitung-worker-out` | 10.89.1.0/24 | no | the worker at 10.89.1.3; egressd at 10.89.1.2 |
| `ahitung-outbound` | 10.89.2.0/24 | yes | egressd only |

The two inner networks are internal and have Podman's DNS disabled. A
container on `ahitung-sandbox` must use `--dns 10.89.0.2`; egressd is then its
only resolver and the only host it can reach.

## The egress policy

egressd allows a connection only if its host matches a rule. Everything else
is refused. The file is JSON:

```json
{
  "rules": [
    {"allow": "pypi.org", "name": "python"},
    {"allow": "**.parapalli.dev"},
    {"allow": "scm.parapalli.dev:8008"}
  ]
}
```

- `allow` is a host pattern:
  - `example.com` matches that host only, never its subdomains.
  - `*.example.com` matches exactly one label in front: `a.example.com`, not
    `a.b.example.com`, not `example.com`.
  - `**.example.com` matches one or more labels in front, and still not
    `example.com`. List the bare domain separately if you want it.
  - `host:port` matches that port only. A bare host matches 443 and any port
    another rule opens.
- `name` is optional and is what the decision log shows; it defaults to the
  pattern.
- Host names are ASCII. Write internationalised names in punycode
  (`xn--…`). IP addresses are refused; allow the name instead.
- Unknown keys are an error, so a misspelt key cannot silently do nothing.
- Wildcards over hosts shared by many tenants (CDNs, `*.s3.amazonaws.com`,
  `raw.githubusercontent.com`, and similar) are refused, because a host rule
  cannot tell one tenant from another there.

Whatever the rules say, egressd never dials a private, loopback, link-local,
or otherwise special-purpose address: if any address a name resolves to is
one, the connection is refused.

Only HTTPS is proxied. egressd reads the server name from the TLS handshake
and splices the encrypted bytes through untouched; it never sees plaintext.
Plain HTTP to an external host has nowhere to go.

### Changing it

Edit `~/.config/ahitung/egressd.json`, then:

```
systemctl --user reload egressd
```

A policy that fails to load is refused and the previous one stays in force;
the reason is in the log as an `ev: config` event. A new `host:port` rule
opens its port on reload. An invalid policy at startup stops egressd from
starting.

DNS answers carry a 30-second TTL, so clients pick up a removed rule within
half a minute; open connections are not cut.

## Reading the decision log

Every DNS answer and every connection is one JSON line in the journal:

```
scripts/logs egressd
journalctl --user -u egressd -o cat | jq -c 'select(.decision == "deny")'
```

Podman's journald driver keeps each line's trailing newline, so `-o cat`
shows a blank line between events; `jq` skips them. Events with
`source_kind: "self"` are egressd's own health check, once a minute.

`rule` names the allow rule that matched, or why the request was refused:
`egress.deny.not_allowed`, `egress.deny.no_sni`, `egress.deny.no_client_hello`,
`egress.deny.invalid_name`, or `egress.deny.<range>` for a special-purpose
address. `decision: "error"` with `egress.error.resolve` or
`egress.error.dial` is an allowed connection that could not be completed.

## Health

The unit runs `/egressd -healthcheck` every minute, which queries egressd's
DNS and opens its TLS port. The service counts as started only once the first
check passes. Check by hand with `podman healthcheck run egressd`.

## Images

Every external image is pinned by tag and digest
(`name:tag@sha256:…`), so a build never changes underneath you.

```
scripts/image-pins            # each pin beside the digest its tag has now
scripts/image-pins --update   # rewrite stale pins in place
```

A new digest is new, unreviewed code: read the diff and the image's changelog
before committing it. Signature verification is not done yet.

## Testing

`ci/egressd-e2e` runs pip, npm, Node `fetch`, git, and curl from throwaway
containers on `ahitung-sandbox`, checks that allowed hosts work and that
unlisted names, unlisted server names, plain HTTP, and IP addresses fail, and
checks the decision log recorded both. It needs the stack up with the example
policy.
