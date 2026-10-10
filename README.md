# Delegates for Corral Light

Which boxes your delegates run on, what each grant allows and until when,
and whether any box is listed that no valid grant covers.

A **grant** is a signed charter: what a delegate may do, and until when. A
**box** is a machine that some **source** reports. The board's unit is the
box, because the question is whether anything is running that no grant
covers.

This is a [Corral Light](https://github.com/cvp1/corral-light) module:
stdlib Python, run by Light's module runner in its sandbox, no network. The
plan it implements is Light's `docs/delegates-module-plan.md` (rev 4);
section numbers below refer to it.

## Install

```
corral-light module add delegates
corral-light delegates setup          # paste your signing public key
corral-light delegates new cal-1      # a charter template; edit it
corral-light delegates sign cal-1     # prints the ssh-keygen command; you run it
```

Then list your boxes by hand in `boxes.toml` next to `config.toml`:

```toml
[[box]]
name = "cal-1"
tier = "delegate"
provider = "gcp"
cost_usd_month = "1.75"
```

## How the board is made

**Grants** come from `charters/<name>.md` (front matter between `---`
lines, signed by a detached `<name>.md.sig` from `ssh-keygen -Y sign`) and
from inbox files other tools drop in `inbox/`. A grant's status is the
first that applies: `bad-charter`, `bad-sig`, `ended:revoked`,
`ended:expired`, `ended:removed`, `unsigned`, `draft`, `valid` (§2.1).

**Required keys:** `name` (must match the filename), `box`, `issued`,
`expires`, and `status` (`draft | approved | revoked`) or the ranch's
`approval`. There is no default for `box` and no typo guessing: a
misspelled required key is a missing one, and the charter is
`bad-charter` (§4.1).

**Boxes** are `<source-id>/<name>`. `boxes.toml` is the source `declared`,
so a bare `box: cal-1` means `declared/cal-1` and nothing else. A grant
lists every qualified name it covers: `box: [cal-1, ranch/cal-1-node]`.
Nothing joins boxes by name across sources (§2.2).

**Presence** is `listed` (a fresh source lists it), `listed-stale`,
`not-listed` (a fresh complete source that covers it omits it, or you
recorded it gone) or `unknown`. A box is **covered** when a `valid` grant
lists it. Listed and uncovered is the alarm, `bad` (§2.3).

**Alarm continuity.** Once a box is `bad`, only three things lower it: a
valid grant that lists it, a fresh complete source reporting it gone (a
deleted `boxes.toml` line), or your gone-record:

```
corral-light delegates gone ranch/cal-1-node --note "terminated 2026-10-10"
```

Deleting a charter, editing `box:`, a failing or stale source, or removing
a source from config never lowers an alarm. The ledger in the module's
data dir carries each box's last presence and each grant's history, with
revocation tombstones kept forever and ordered by the signed `issued`
key, so a restored older file stays revoked (§2.4).

**Signatures** verify with `ssh-keygen -Y verify` against
`allowed_signers`, which `setup` writes with `namespaces=` (ssh-keygen
alone accepts a line without it; the module refuses one). In v1 this runs
on Linux only: the macOS module sandbox allows no child process, so there
every signed charter reads `bad-sig: cannot verify` and the board says so.
A core-provided verifier is planned (§3, Phase 2).

**The inbox** (`inbox/*.json`, schema `corral-light.delegates.inbox/1`)
takes files declared under `[[source]]` in `config.toml`. Each grant must
carry `grant_id`, `issued`, `expires`, `box` and `signature` (`verified |
failed | absent | unverified`); only `verified` and `approved: true` can
make an inbox grant valid. `contrib/ranch_status_to_inbox.py` converts
the ranch's `delegates/status.py --json`, reading each charter file
beside it for the bytes to hash and the `created` key (§4.3).

**The board is not proof.** "Box listed" means a source says a box
exists. It does not mean the box is up, is the machine the charter meant,
or obeys the charter. Every row names its sources and their ages.

## Verbs

| Verb | Does |
|---|---|
| `setup` | paste a public key; writes `allowed_signers`, `config.toml`, `charters/`, `inbox/` |
| `show [--json]` | the board as text, or the raw snapshot |
| `doctor` | how each source is read, verification, the ledger, anything wrong |
| `new <name>` | a charter template |
| `sign <name>` | prints the exact `ssh-keygen -Y sign` command; never signs |
| `check` | every grant's status and every uncovered box |
| `gone <source>/<name>` | records a box as gone (refused while a fresh source lists it) |
| `ack-ledger` | acknowledges a damaged ledger or tombstone file; the one CLI write to the data dir |

## Tests

```
cd tests && python -m unittest discover -v
```

The signature cases need `ssh-keygen` and run on Linux. `tests/light_contract.py`
is Light's own manifest and snapshot validator, vendored verbatim; re-vendor
with `tests/vendor_contract.py` when Light's contract changes.

## Licence

MIT.
