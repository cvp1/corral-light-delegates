"""Small shared helpers: the module's environment, time, files."""
import hashlib
import os
import re
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone

DAY = 86400
RETENTION_S = 30 * DAY          # ledger history after a box is not-listed (plan §2.4)
SHOW_REMOVAL_S = 7 * DAY        # hand removals and gone-records in Sources (§4.2)
SKEW_S = 600                    # inbox generated_at, and issued, ahead of now (§2.5)
CLOCK_BACK_S = 300              # clock warning (§2.5)
EXPIRING_S = 72 * 3600          # "expiring soon" (§5)


class Env:
    """What Light hands the module (plan §3). Tests build one directly; the
    entry points use from_environ()."""

    def __init__(self, data, config=None, sandboxed=True, tz=None, now=None,
                 platform=None, api=None):
        self.data = data
        self.config = config                      # path of config.toml
        self.sandboxed = sandboxed
        self.tz = tz
        self._now = now
        self.platform = platform or sys.platform
        self.api = api

    @classmethod
    def from_environ(cls, environ=None):
        e = os.environ if environ is None else environ
        data = e.get("CORRAL_MODULE_DATA")
        if not data:
            raise SystemExit("delegates: CORRAL_MODULE_DATA is not set; this runs under "
                             "corral-light (corral-light module run delegates)")
        return cls(data=data, config=e.get("CORRAL_MODULE_CONFIG") or None,
                   sandboxed=e.get("CORRAL_MODULE_SANDBOXED", "1") == "1",
                   tz=e.get("TZ") or None, api=e.get("CORRAL_MODULE_API"))

    @property
    def config_dir(self):
        return os.path.dirname(self.config) if self.config else None

    def now(self):
        return self._now if self._now is not None else time.time()

    def can_verify(self):
        """Whether this run may start ssh-keygen (plan §3): the macOS sandbox
        denies process-fork, so v1 verifies on Linux only."""
        return not (self.platform == "darwin" and self.sandboxed)


# ── time ────────────────────────────────────────────────────────────────────

_RFC = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.(\d{1,9}))?"
                  r"\s*(Z|z|[+-]\d{2}:?\d{2})?$")
_DATE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")
_COMPACT = re.compile(r"^(\d{4})-?(\d{2})-?(\d{2})T(\d{2})(\d{2})(\d{2})(Z|[+-]\d{2}:?\d{2})?$")


def _epoch(y, mo, d, h, mi, s, tzs):
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=timezone.utc)
    except ValueError:
        return None
    if tzs and tzs not in ("Z", "z"):
        sign = 1 if tzs[0] == "+" else -1
        hh, mm = int(tzs[1:3]), int(tzs[-2:])
        dt -= sign * timedelta(hours=hh, minutes=mm)
    return (dt - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds()


def parse_time(v, bare="end"):
    """A charter or inbox time (plan §2.5) -> (epoch seconds, None) or
    (None, reason). Forms: RFC 3339 with Z or an offset (`+00:00`, `-0700`);
    a bare date, meaning 23:59:59Z (`bare="end"`) or 00:00:00Z (`"start"`).
    A date-time with no zone is refused."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return (float(v), None) if v > 0 else (None, "unparseable")
    if not isinstance(v, str) or not v.strip():
        return None, "missing"
    s = v.strip()
    m = _DATE.match(s)
    if m:
        y, mo, d = m.groups()
        ts = _epoch(y, mo, d, 23, 59, 59, "Z") if bare == "end" else _epoch(y, mo, d, 0, 0, 0, "Z")
        return (ts, None) if ts is not None else (None, "invalid date")
    m = _RFC.match(s)
    if m:
        y, mo, d, h, mi, sec, _frac, tzs = m.groups()
        if not tzs:
            return None, "no zone"
        ts = _epoch(y, mo, d, h, mi, sec or 0, tzs)
        return (ts, None) if ts is not None else (None, "invalid date")
    return None, "unparseable"


def parse_compact(v):
    """`2026-08-16T000000Z` or `20260816T000000Z` (ranch audit stamps), or any
    form parse_time takes -> epoch seconds or None."""
    if not isinstance(v, str):
        return None
    m = _COMPACT.match(v.strip())
    if m:
        y, mo, d, h, mi, s, tzs = m.groups()
        return _epoch(y, mo, d, h, mi, s, tzs or "Z")
    ts, _ = parse_time(v, bare="start")
    return ts


def utc_iso(s):
    return datetime.fromtimestamp(s, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_date(s):
    return datetime.fromtimestamp(s, timezone.utc).strftime("%Y-%m-%d")


def age_text(seconds):
    seconds = max(0, int(seconds))
    if seconds < 120:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{seconds // 60} min"
    if seconds < 2 * DAY:
        return f"{seconds // 3600} h"
    return f"{seconds // DAY} d"


def in_text(seconds):
    """'in 41 h', 'in 3 d'; past times as '<age> ago'."""
    if seconds < 0:
        return age_text(-seconds) + " ago"
    return "in " + age_text(seconds)


# ── files ──────────────────────────────────────────────────────────────────

def atomic_write(path, text, mode=0o600):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, f".{os.path.basename(path)}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_capped(path, cap):
    """-> (bytes, over) for a regular file; `over` when the file is larger
    than cap (the bytes are then the first cap). Symlinks are refused:
    raises OSError."""
    st = os.lstat(path)
    if not os.path.isfile(path) or os.path.islink(path):
        raise OSError(f"{path}: not a regular file")
    with open(path, "rb") as f:
        data = f.read(cap + 1)
    return data[:cap], len(data) > cap or st.st_size > cap


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def short_id(gid):
    """`sha256:3f9c…` -> `3f9c1a2b` for display."""
    if not gid:
        return "-"
    return gid.split(":", 1)[-1][:10]
