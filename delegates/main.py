"""Entry points: the collector and the CLI verbs (plan §6)."""
import json
import os
import re
import sys

from delegates import VERSION, charter, ledger as ledger_mod, model, sources, util, view
from delegates.charter import DEFAULT_NAMESPACE, NAME_RE
from delegates.sources import Config, ConfigError

USAGE = """usage: corral-light delegates <verb>
  setup                 paste your signing public key; writes allowed_signers and config.toml
  show [--json]         the board as text (or the raw snapshot)
  doctor                how each source is read, and anything wrong
  new <name>            write a charter template in charters/
  sign <name>           print the ssh-keygen command that signs a charter (never signs)
  check                 parse and verify every charter; print each grant's status
  gone <source>/<name> [--note TEXT]
                        record that a box is gone (plan §2.4)
  ack-ledger            acknowledge a damaged ledger or tombstone file"""

LAST_CLI = ".cli-last"


def _opt(args, name, default=None):
    if name in args:
        i = args.index(name)
        if i + 1 < len(args):
            v = args[i + 1]
            del args[i:i + 2]
            return v
    return default


# ── one evaluation ─────────────────────────────────────────────────────────

def run(env, runner=None, save=True):
    """Read everything, evaluate, write the ledger. -> (board, snapshot)."""
    now = env.now()
    cfg = Config.load(env.config)
    charters, csrc = sources.load_charters(cfg)
    declared = sources.load_declared(cfg, now)
    inbox = sources.load_inbox(cfg, now, env.data if save else None)
    gone, gone_errors = sources.load_gone(cfg)
    led = ledger_mod.Ledger(env.data, now)
    cache = model.open_sigcache(env) if save else None
    signers = sources.read_signers(cfg)
    board = model.evaluate(env, cfg, charters, declared, inbox, gone, led, sigcache=cache,
                           signers_text=signers, runner=runner, charters_source=csrc)
    board.gone_errors = gone_errors
    board.undeclared = sources.undeclared_files(cfg)
    snap = view.build(env, cfg, board, led)
    if save:
        led.save()
        if cache is not None:
            cache.save()
    return board, snap


# ── collector ──────────────────────────────────────────────────────────────

def collector_main(argv, env=None, out=None, runner=None):
    out = out or sys.stdout
    args = list(argv)
    if args[:1] != ["snapshot"]:
        print("delegates collector: expected `snapshot`", file=sys.stderr)
        return 2
    env = env or util.Env.from_environ()
    try:
        _board, snap = run(env, runner=runner)
    except ConfigError as e:
        print(f"delegates: {e}", file=sys.stderr)
        return 1
    except Exception as e:                            # noqa: BLE001
        print(f"delegates: {type(e).__name__}: {str(e)[:300]}", file=sys.stderr)
        return 1
    out.write(json.dumps(snap, separators=(",", ":")) + "\n")
    out.flush()
    return 0


# ── CLI ────────────────────────────────────────────────────────────────────

def _note_cli(env, verb):
    """Remember the last CLI verb in the config folder (doctor's inbox check)."""
    cfg_dir = env.config_dir
    if not cfg_dir:
        return
    try:
        util.atomic_write(os.path.join(cfg_dir, LAST_CLI), f"{verb} {util.utc_iso(env.now())}\n")
    except OSError:
        pass


def cli_main(argv, env=None, out=None, ask=None, runner=None):
    out = out or sys.stdout
    args = list(argv)
    if not args or args[0] in ("-h", "--help", "help"):
        print(USAGE, file=out)
        return 0 if args else 2
    verb, rest = args[0], args[1:]
    env = env or util.Env.from_environ()
    try:
        if verb == "setup":
            rc = setup(env, out=out, ask=ask)
        elif verb == "show":
            rc = show(env, as_json="--json" in rest, out=out, runner=runner)
        elif verb == "doctor":
            rc = doctor(env, out=out, runner=runner)
        elif verb == "new":
            rc = new(env, rest, out=out)
        elif verb == "sign":
            rc = sign(env, rest, out=out)
        elif verb == "check":
            rc = check(env, out=out, runner=runner)
        elif verb == "gone":
            rc = gone(env, rest, out=out, runner=runner)
        elif verb == "ack-ledger":
            rc = ack_ledger(env, out=out)
        else:
            print(USAGE, file=sys.stderr)
            return 2
    except ConfigError as e:
        print(f"delegates: {e}", file=sys.stderr)
        return 1
    _note_cli(env, verb)
    return rc


def _ask_tty(prompt):
    if not sys.stdin.isatty():
        return None
    try:
        return input(prompt).strip()
    except EOFError:
        return None


_KEY_LINE = re.compile(r"^(?P<type>(?:ssh|sk-ssh|ecdsa|sk-ecdsa)-[A-Za-z0-9.@-]+)\s+(?P<key>[A-Za-z0-9+/=]+)(?:\s+(?P<comment>\S.*))?$")
_PRINCIPAL = re.compile(r"^[A-Za-z0-9._@+-]{1,64}$")


def setup(env, out=sys.stdout, ask=None):
    """Paste a public key line; write allowed_signers (with `namespaces=`),
    config.toml, charters/ and inbox/ (plan §6)."""
    ask = ask or _ask_tty
    cfg = Config.load(env.config)
    if not cfg.dir:
        raise ConfigError("no config path (CORRAL_MODULE_CONFIG is not set)")
    if cfg.error:
        print(cfg.error + "; fix or remove the file, then run setup again.", file=out)
        return 1
    if ask is _ask_tty and not sys.stdin.isatty():
        print("setup needs a terminal to ask for your public key; run it in one.", file=out)
        return 1
    os.makedirs(cfg.dir, mode=0o700, exist_ok=True)
    for sub in ("charters", "inbox"):
        os.makedirs(os.path.join(cfg.dir, sub), mode=0o700, exist_ok=True)
    signers_path = cfg.signers_path()
    have = os.path.exists(signers_path)
    print("Delegates verifies charter signatures with ssh-keygen -Y verify against", file=out)
    print(f"{signers_path}.", file=out)
    if have:
        print("It exists. Paste another public key line to add a signer, or Enter to keep it.", file=out)
    else:
        print("Paste the PUBLIC key line of the key you sign charters with (the contents of", file=out)
        print("its .pub file, e.g. `sk-ssh-ed25519@openssh.com AAAA... you@host`). Enter to skip,", file=out)
        print("which leaves signing off until you run setup again.", file=out)
    line = (ask("Public key line: ") or "").strip()
    added = False
    if line:
        m = _KEY_LINE.match(line)
        if not m:
            print("that is not a public key line (type, base64 key, optional comment).", file=out)
            return 1
        comment = (m.group("comment") or "").strip()
        default = comment.split()[0] if comment and _PRINCIPAL.match(comment.split()[0]) else "operator"
        principal = (ask(f"Principal name for this key [{default}]: ") or default).strip()
        if not _PRINCIPAL.match(principal):
            print("a principal is letters, digits and . _ @ + -", file=out)
            return 1
        ns = DEFAULT_NAMESPACE
        entry = f'{principal} namespaces="{ns}" {m.group("type")} {m.group("key")}\n'
        text = ""
        if have:
            with open(signers_path, encoding="utf-8") as f:
                text = f.read()
            if not text.endswith("\n"):
                text += "\n"
        util.atomic_write(signers_path, text + entry)
        cfg.charters[0]["principal"] = principal
        cfg.charters[0]["namespace"] = ns
        cfg.require_signature = "yes"
        added = True
        print(f"  wrote {signers_path}: {principal}, namespaces=\"{ns}\"", file=out)
    elif not have:
        cfg.require_signature = "no"
        print("  no key; signing stays off (require_signature = \"no\").", file=out)
    cfg.save()
    print(f"Saved {cfg.path}.", file=out)
    print(f"Charters go in {os.path.join(cfg.dir, 'charters')}; inbox files in "
          f"{os.path.join(cfg.dir, 'inbox')} (declare each under [[source]] in config.toml).", file=out)
    if added:
        print("Next: `corral-light delegates new <name>`, edit it, then `sign <name>`.", file=out)
    return 0


def show(env, as_json=False, out=sys.stdout, runner=None):
    _board, snap = run(env, runner=runner, save=False)
    if as_json:
        print(json.dumps(snap, indent=2), file=out)
    else:
        print(view.render_text(snap), file=out)
    return 0


def check(env, out=sys.stdout, runner=None):
    board, _snap = run(env, runner=runner, save=False)
    p = lambda *a: print(*a, file=out)  # noqa: E731
    if not board.grants:
        p("No grants: no charters in charters/ and no inbox grants.")
    for g in sorted(board.grants, key=lambda g: (model.STATUS_RANK.get(g.status, 9), g.qname)):
        p(f"{g.qname:34} {g.status:16} {g.reason}")
        p(f"{'':34} box: {', '.join(g.boxes) or '-'}; signature: {g.sig} ({g.sig_reason})")
    bad = [b for b in board.boxes if b.level == "bad"]
    p("")
    p(f"{len(board.boxes)} box(es) in scope, {len(bad)} without a valid grant.")
    for b in bad:
        p(f"  {b.id}: {b.label}")
    return 0


def doctor(env, out=sys.stdout, runner=None):
    p = lambda *a: print(*a, file=out)  # noqa: E731
    cfg = Config.load(env.config)
    p(f"Delegates {VERSION}, {'sandboxed' if env.sandboxed else 'UNSANDBOXED (acknowledged)'}, "
      f"platform {env.platform}")
    p(f"Config: {cfg.path or '(none)'}" + (f" — {cfg.error}" if cfg.error else ""))
    p(f"Signing required: {'yes' if cfg.signing_required() else 'no'} "
      f"(require_signature = \"{cfg.require_signature}\"; allowed_signers "
      f"{'present' if cfg.signers_path() and os.path.exists(cfg.signers_path()) else 'absent'})")
    if not env.can_verify():
        p("Verification: NOT possible on this host (macOS sandbox: no child process). Every "
          "signed charter reads bad-sig: cannot verify. Plan Phase 2 adds a core-provided verifier.")
    else:
        p(f"Verification: ssh-keygen {'found at ' + charter.keygen_path() if charter.keygen_path() else 'NOT FOUND'}")
    for f in cfg.charters:
        d = cfg.folder_path(f)
        n = len([x for x in os.listdir(d) if x.endswith('.md')]) if os.path.isdir(d) else None
        p(f"Charters: {d} ({'missing' if n is None else str(n) + ' .md files'}); principal "
          f"{f.get('principal') or '(first in allowed_signers)'}; namespace {f.get('namespace')}")
    inbox = cfg.inbox_dir()
    p(f"Inbox: {inbox or '(none)'} ({'present' if inbox and os.path.isdir(inbox) else 'missing'}); "
      f"{len(cfg.sources)} declared source(s)")
    if inbox and os.path.islink(inbox):
        p("  WARNING: inbox/ is a symlink; the collector refuses it")
    board, _snap = run(env, runner=runner, save=False)
    for s in board.sources:
        p(f"  {s.id:12} {s.health:8} {s.age_text(board.now):>8}  {len(s.boxes)} boxes, {len(s.grants)} grants"
          + ("  " + "; ".join(s.errors + s.notes) if s.errors or s.notes else ""))
    for fn in board.undeclared:
        p(f"  undeclared inbox file: {fn}")
    # the §3 warning: inbox newer than the last collector run while setup was the last CLI verb
    last = _last_cli(env)
    led = board.ledger
    if inbox and os.path.isdir(inbox) and led.last_run and last and last[0] == "setup":
        newer = [fn for fn in os.listdir(inbox)
                 if os.path.isfile(os.path.join(inbox, fn)) and os.path.getmtime(os.path.join(inbox, fn)) > led.last_run]
        if newer:
            p(f"WARNING: inbox file(s) newer than the last collector run while `setup` was the last "
              f"CLI command: {', '.join(newer)}. The CLI can write the inbox (plan §3); check them.")
    for level, text in led.damage_rows():
        p(f"Ledger: [{level}] {text}")
    p(f"Ledger: {led.size_text()}; last run {util.utc_iso(led.last_run) if led.last_run else 'never'}")
    if board.clock_warning:
        p("Clock: behind the last run; countdowns are uncertain")
    bad = [b for b in board.boxes if b.level == "bad"]
    p(f"Board: {len(board.boxes)} box(es) in scope, {len(bad)} without a valid grant, "
      f"{len(board.grants)} grant(s)")
    for g in board.gone_errors:
        p(f"gone.toml: {g}")
    return 0


def _last_cli(env):
    d = env.config_dir
    if not d:
        return None
    try:
        with open(os.path.join(d, LAST_CLI), encoding="utf-8") as f:
            parts = f.read().split()
        return (parts[0], parts[1]) if len(parts) >= 2 else None
    except OSError:
        return None


TEMPLATE = """---
name: {name}
status: approved
issued: {issued}
expires: {expires}
box: {name}
data-class: internal
capabilities: []
cost-box-usd-month:
---

What this delegate is for, in your words.

Edit `box:` to the box this grant covers: a bare name is a box in boxes.toml
(`declared/<name>`); `ranch/cal-1-node` names a box another source reports.
Then sign: corral-light delegates sign {name}
"""


def new(env, rest, out=sys.stdout):
    cfg = Config.load(env.config)
    if not rest or not NAME_RE.match(rest[0]):
        print("usage: new <name>  (a-z, digits and - ; up to 61 characters)", file=out)
        return 2
    name = rest[0]
    d = cfg.folder_path(cfg.charters[0])
    os.makedirs(d, mode=0o700, exist_ok=True)
    p = os.path.join(d, name + ".md")
    if os.path.lexists(p):
        print(f"{p} exists; not overwritten.", file=out)
        return 1
    now = env.now()
    text = TEMPLATE.format(name=name, issued=util.utc_iso(now), expires=util.utc_date(now + 30 * util.DAY))
    util.atomic_write(p, text, mode=0o644)
    print(f"Wrote {p} (issued now, expires in 30 days). Edit it, then: corral-light delegates sign {name}", file=out)
    return 0


def sign(env, rest, out=sys.stdout):
    cfg = Config.load(env.config)
    if not rest or not NAME_RE.match(rest[0]):
        print("usage: sign <name>", file=out)
        return 2
    folder = cfg.charters[0]
    p = os.path.join(cfg.folder_path(folder), rest[0] + ".md")
    if not os.path.exists(p):
        print(f"no charter {p}", file=out)
        return 1
    ns = folder.get("namespace") or DEFAULT_NAMESPACE
    print("Delegates never signs. Run this with the private key you set up (replace KEYFILE;", file=out)
    print("for a hardware key it is the sk- key handle file, e.g. ~/.ssh/id_ed25519_sk):", file=out)
    print("", file=out)
    print("  " + charter.sign_command("KEYFILE", ns, p), file=out)
    print("", file=out)
    print(f"That writes {p}.sig. To revoke or renew, change issued to now, edit, and sign again.", file=out)
    return 0


def gone(env, rest, out=sys.stdout, runner=None):
    args = list(rest)
    note = _opt(args, "--note", "") or ""
    if not args or "/" not in args[0]:
        print("usage: gone <source>/<name> [--note TEXT]", file=out)
        return 2
    bid = args[0]
    cfg = Config.load(env.config)
    if not cfg.dir:
        raise ConfigError("no config path (CORRAL_MODULE_CONFIG is not set)")
    board, _snap = run(env, runner=runner, save=False)
    box = next((b for b in board.boxes if b.id == bid), None)
    if box is None:
        print(f"{bid} is not an in-scope box (nothing lists or names it). Nothing recorded.", file=out)
        return 1
    fresh = [s for s, h, _g in box.listed_by if h == "fresh"]
    if fresh:
        src = next(s for s in board.sources if s.id == fresh[0])
        print(f"{src.id} lists {bid} as of {src.age_text(board.now)} ago; stop it first. Nothing recorded.", file=out)
        return 1
    sources.append_gone(cfg, bid, env.now(), note)
    print(f"Recorded: {bid} gone as of {util.utc_iso(env.now())} in {os.path.join(cfg.dir, 'gone.toml')}. "
          f"It reads not-listed from the next run; a later listing by a source reinstates it.", file=out)
    return 0


def ack_ledger(env, out=sys.stdout):
    led = ledger_mod.Ledger(env.data, env.now())
    if not led.damage:
        print("Nothing to acknowledge: no damage recorded.", file=out)
        return 0
    ledger_mod.write_ack(env.data, env.now())
    print(f"Acknowledged. The record stays in Sources as information for 30 days; tombstones were "
          f"not touched ({len(led.tombstones)} kept).", file=out)
    return 0
