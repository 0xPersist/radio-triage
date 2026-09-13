#!/usr/bin/env python3
"""
radio-triage — Android radio log triage for telephony debugging.

Parses the radio logcat buffer (threadtime format) into a telephony event
timeline and flags anomalies: service loss, RAT downgrades (weighted toward
2G-family destinations), IMS deregistrations, registration flapping, and
explicit reject causes.

Input is produced by capture-radio.sh (bundled) or manually via:
    adb logcat -b radio -v threadtime -d > radio.txt

Usage:
    radio_triage.py --log radio.txt
    radio_triage.py --log radio.txt --json
    radio_triage.py --log radio.txt --timeline        (full event timeline)

Security posture: log content is treated as untrusted input (network-side
behavior influences it). Output is sanitized against terminal escape
injection; subscriber-identifying values are redacted by default; input is
size-capped and hashed.

No dependencies beyond the Python standard library. Python 3.8+.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_FILE_BYTES = 128 * 1024 * 1024   # radio buffers can be large
MAX_EVENTS = 500_000

CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

# logcat -v threadtime: "MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG : message"
THREADTIME_RE = re.compile(
    r"^(?P<ts>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEF])\s+"
    r"(?P<tag>[^:]{1,64}?)\s*:\s(?P<msg>.*)$")

# Radio Access Technology ranking for downgrade detection. Higher = newer.
RAT_RANK = {
    "NR": 5, "NR_SA": 5, "NR_NSA": 5,
    "LTE": 4, "LTE_CA": 4,
    "HSPAP": 3, "HSPA": 3, "HSDPA": 3, "HSUPA": 3, "UMTS": 3, "TD_SCDMA": 3,
    "EDGE": 2, "GPRS": 2, "GSM": 2,
    "UNKNOWN": 0,
}
TWO_G = {"EDGE", "GPRS", "GSM"}

RAT_TOKEN_RE = re.compile(
    r"\b(NR_SA|NR_NSA|NR|LTE_CA|LTE|HSPAP|HSDPA|HSUPA|HSPA|UMTS|TD_SCDMA|"
    r"EDGE|GPRS|GSM)\b")

SERVICE_STATES = ("OUT_OF_SERVICE", "EMERGENCY_ONLY", "IN_SERVICE",
                  "POWER_OFF")

# Phone/slot hint in log messages; multi-SIM logs interleave phones, and
# tracking them globally produces false cross-slot transitions.
PHONE_HINT_RE = re.compile(r"(?:phoneId|phone_id|slotId|slotIndex)\s*[=:]\s*(\d)")
PHONE_PREFIX_RE = re.compile(r"^\[(\d)\]")

# Redaction: subscriber-identifying patterns inside free-text log messages.
# Value-pattern based (not key based) because log lines are unstructured.
REDACT_PATTERNS = (
    # E.164-ish phone numbers
    re.compile(r"\+\d{7,15}"),
    # Separator-formatted IMEI/IMSI: 35-209900-176148-1, 35 209900 176148 1.
    # Must precede the bare-digit rule so the whole grouped form is replaced
    # as one token rather than piecemeal.
    re.compile(r"\b\d{2}[- ]\d{6}[- ]\d{6}[- ]\d\b"),
    # Bare digit runs. Widened from 13-20 to 10-20: an unprefixed national or
    # country-code phone number (4075551234, 14075551234) sat in the old gap
    # and printed in the clear. 10 is the floor because that is the shortest
    # subscriber number in practice; 9 and below is left alone so ordinary
    # numeric log fields stay readable.
    re.compile(r"\b\d{10,20}\b"),
    # explicit labeled identifiers
    re.compile(r"\b(?:imsi|iccid|imei|msisdn)\s*[=:]\s*\S+", re.IGNORECASE),
    # cell identity fields
    re.compile(r"\b(?:mCi|cellIdentity|ci|pci|tac|cid|lac)\s*=\s*\d+"),
)

FLAP_WINDOW_SECONDS = 120     # elapsed-time window for flap detection
FLAP_TRANSITIONS = 4          # service transitions within window => flapping

# Stamp broken into fields so it can be ordered and differenced. The year is
# optional because plain `logcat -v threadtime` omits it (see Clock).
TS_RE = re.compile(
    r"^(?:(?P<year>\d{4})-)?(?P<mon>\d{2})-(?P<day>\d{2})\s+"
    r"(?P<h>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})\.(?P<frac>\d+)$")

# Cumulative days before each month using a leap-year table (February = 29).
# Every year is treated as 366 days: ordering stays exact, because the largest
# in-year offset (Dec 31 -> 366) is still below the next year's Jan 1 (367),
# and elapsed time is only ever compared against a 120-second window, where
# the one-day difference between a leap and a common year cannot matter. A
# fixed table also lets a Feb 29 stamp parse under an inferred year, which
# datetime() would reject outright.
_CUM_DAYS = (0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335)


class Clock:
    """Turns a logcat stamp into one comparable number of seconds.

    `logcat -v threadtime` omits the year, so a capture crossing New Year
    sorts January ahead of December on the raw string, and the gap across the
    boundary reads as negative. When the year is absent it is inferred: a
    running counter starts at 0 and increments whenever the month goes
    backwards (a 12 -> 01 wrap). That is correct for at most one year boundary
    per capture, which is the documented assumption -- capture with
    `-v year` to avoid the inference entirely.
    """

    def __init__(self) -> None:
        self.year = 0
        self.prev_mon = None

    def seconds(self, ts: str) -> float:
        """Absolute seconds for `ts`, or 0.0 if it is not a usable stamp.

        Returning 0.0 rather than raising keeps crafted input (month 13, day
        99) from aborting a triage run; such an event simply sorts first.
        """
        m = TS_RE.match(ts)
        if not m:
            return 0.0
        mon, day = int(m.group("mon")), int(m.group("day"))
        if not (1 <= mon <= 12 and 1 <= day <= 31):
            return 0.0
        if m.group("year") is not None:
            self.year = int(m.group("year"))
        elif self.prev_mon is not None and mon < self.prev_mon:
            self.year += 1
        self.prev_mon = mon
        day_no = self.year * 366 + _CUM_DAYS[mon - 1] + day
        return (day_no * 86400.0
                + int(m.group("h")) * 3600
                + int(m.group("min")) * 60
                + int(m.group("sec"))
                + float("0." + m.group("frac")))


# ---------------------------------------------------------------------------
# Security primitives
# ---------------------------------------------------------------------------

def sanitize(s: str) -> str:
    """Neutralize terminal control characters (escape injection defense)."""
    return CTRL_RE.sub(lambda m: f"\\x{ord(m.group(0)):02x}", s)


def redact(msg: str, enabled: bool) -> str:
    """Replace subscriber-identifying substrings with stable short hashes."""
    if not enabled:
        return msg
    def _sub(m: re.Match) -> str:
        h = hashlib.sha256(m.group(0).encode("utf-8", "replace"))
        return f"[REDACTED:{h.hexdigest()[:8]}]"
    for pat in REDACT_PATTERNS:
        msg = pat.sub(_sub, msg)
    return msg


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

@dataclass
class Event:
    ts: str
    tag: str
    kind: str        # service_state | rat | ims | sim | radio_power | reject
    detail: str      # normalized detail (state name, RAT token, cause...)
    raw: str         # original message (redacted/sanitized only at output)
    phone: str = "0" # phone/slot hint (default 0 when absent)
    order: float = 0.0  # (year, month, day, time) flattened to seconds


@dataclass
class Parsed:
    path: str
    sha256: str = ""
    events: list = field(default_factory=list)
    lines_total: int = 0
    lines_matched: int = 0


def classify(tag: str, msg: str) -> list[tuple[str, str]]:
    """Extract zero or more (kind, detail) events from one log message."""
    out: list[tuple[str, str]] = []

    # Transition lines read "oldState -> newState": the RIGHTMOST state
    # token is the new state. Taking the first misreads recoveries as
    # outages (audit finding M1).
    best_pos, best_state = -1, None
    for state in SERVICE_STATES:
        pos = msg.rfind(state)
        if pos > best_pos:
            best_pos, best_state = pos, state
    if best_state is not None:
        out.append(("service_state", best_state))

    rats = list(RAT_TOKEN_RE.finditer(msg))
    if rats and ("RegState" in msg or "ServiceState" in msg or "rat=" in msg
                 or "RadioTechnology" in msg or "NetworkType" in msg
                 or "accessNetwork" in msg):
        # Rightmost token = current/new RAT on transition lines (audit M2).
        out.append(("rat", rats[-1].group(1)))

    low = msg.lower()
    if "ims" in low and ("deregist" in low or "unregist" in low):
        out.append(("ims", "DEREGISTERED"))
    elif ("ims" in low and "regist" in low
          and not re.search(r"\bnot\s+regist", low)):
        out.append(("ims", "REGISTERED"))

    if "SIM_STATE" in msg or "simState" in msg:
        out.append(("sim", "SIM_STATE_EVENT"))

    if "setRadioPower" in msg or "RADIO_POWER" in msg:
        out.append(("radio_power", "POWER_EVENT"))

    # cause=0 means "no cause given" and is routine in live captures, so it
    # must not raise a reject. `(?!0+\b)` rejects any all-zero value: 0, 00,
    # 000. A leading zero on a real cause (01, 017) still fires, because 0+
    # cannot reach a word boundary there.
    m = re.search(
        r"(?:rejectCause|reject_cause|denyCause|failCause)\s*[=:]\s*"
        r"(?!0+\b)(\d+)"
        r"|regState=DENIED"
        r"|registration.{0,20}denied", msg, re.IGNORECASE)
    if m:
        out.append(("reject", m.group(0)))

    return out


def parse_log(path: str) -> Parsed:
    p = Parsed(path=path)
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_FILE_BYTES + 1)
    except OSError as e:
        sys.exit(f"error: cannot read {path}: {e}")
    if len(data) > MAX_FILE_BYTES:
        sys.exit(f"error: {path} exceeds {MAX_FILE_BYTES} byte cap"
                 " (crafted-input guard)")
    p.sha256 = hashlib.sha256(data).hexdigest()

    clock = Clock()
    for raw in data.decode("utf-8", errors="replace").splitlines():
        p.lines_total += 1
        m = THREADTIME_RE.match(raw)
        if not m:
            continue
        p.lines_matched += 1
        tag = m.group("tag").strip()
        msg = m.group("msg")
        ph = PHONE_HINT_RE.search(msg) or PHONE_PREFIX_RE.match(msg)
        phone = ph.group(1) if ph else "0"
        # Advance the clock once per line, not once per event: one line can
        # yield several events and the year inference is line-sequential.
        order = clock.seconds(m.group("ts"))
        for kind, detail in classify(tag, msg):
            if len(p.events) >= MAX_EVENTS:
                sys.exit(f"error: {path} produced more than {MAX_EVENTS}"
                         " events, refusing to continue"
                         " (crafted-input guard)")
            p.events.append(Event(m.group("ts"), tag, kind, detail, msg,
                                  phone, order))
    return p


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

@dataclass
class Anomaly:
    ts: str
    severity: str    # HIGH | MEDIUM | LOW
    kind: str
    summary: str
    raw: str
    order: float = 0.0


def collapse(anomalies: list[Anomaly]) -> list[Anomaly]:
    """Group identical (severity, kind, summary) anomalies across the whole
    report into one entry with count and first..last time span, preserving
    first-occurrence order. Live captures repeat routine transitions many
    times, often interleaved across phones; adjacency-only merging is not
    enough."""
    order: list[tuple] = []
    groups: dict[tuple, dict] = {}
    for a in anomalies:
        key = (a.severity, a.kind, a.summary)
        if key not in groups:
            groups[key] = {"first": a.ts, "last": a.ts, "n": 1,
                           "raw": a.raw, "order": a.order}
            order.append(key)
        else:
            g = groups[key]
            g["last"] = a.ts
            g["n"] += 1
            g["raw"] = a.raw
    out: list[Anomaly] = []
    for key in order:
        sev, kind, summary = key
        g = groups[key]
        if g["n"] > 1:
            summary = f"{summary} [x{g['n']}, {g['first']} .. {g['last']}]"
        out.append(Anomaly(g["first"], sev, kind, summary, g["raw"],
                           g["order"]))
    return out


def detect_anomalies(p: Parsed) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    # All state tracked PER PHONE/SLOT: multi-SIM logs interleave phones,
    # and global tracking fabricates cross-slot transitions (audit M3).
    last_rat: dict[str, str] = {}
    last_service: dict[str, str] = {}
    service_transitions: dict[str, list[float]] = {}

    for i, ev in enumerate(p.events):
        ph = ev.phone
        if ev.kind == "service_state":
            prev = last_service.get(ph)
            if prev is not None and ev.detail != prev:
                service_transitions.setdefault(ph, []).append(ev.order)
                if ev.detail in ("OUT_OF_SERVICE", "EMERGENCY_ONLY"):
                    anomalies.append(Anomaly(
                        ev.ts, "HIGH", "service_loss",
                        f"phone{ph}: service transition {prev} ->"
                        f" {ev.detail}", ev.raw, ev.order))
            last_service[ph] = ev.detail

            # Elapsed time, not event count: a handful of transitions spread
            # over ten minutes is not flapping, however few events sit
            # between them. Pruning here also bounds the list.
            recent = [t for t in service_transitions.get(ph, [])
                      if ev.order - t <= FLAP_WINDOW_SECONDS]
            service_transitions[ph] = recent
            if len(recent) >= FLAP_TRANSITIONS:
                anomalies.append(Anomaly(
                    ev.ts, "MEDIUM", "registration_flapping",
                    f"phone{ph}: {len(recent)} service transitions within"
                    f" {FLAP_WINDOW_SECONDS} s", ev.raw, ev.order))
                service_transitions[ph] = []

        elif ev.kind == "rat":
            prev = last_rat.get(ph)
            if (prev is not None
                    and RAT_RANK.get(ev.detail, 0)
                    < RAT_RANK.get(prev, 0)):
                to_2g = ev.detail in TWO_G
                anomalies.append(Anomaly(
                    ev.ts, "HIGH" if to_2g else "LOW", "rat_downgrade",
                    f"phone{ph}: RAT downgrade {prev} -> {ev.detail}"
                    + (" (2G family: cell-site-simulator relevant,"
                       " verify with RF-side capture)" if to_2g else ""),
                    ev.raw, ev.order))
            last_rat[ph] = ev.detail

        elif ev.kind == "ims" and ev.detail == "DEREGISTERED":
            anomalies.append(Anomaly(
                ev.ts, "MEDIUM", "ims_deregistration",
                "IMS deregistered (voice-over-LTE/NR impact)", ev.raw,
                ev.order))

        elif ev.kind == "reject":
            anomalies.append(Anomaly(
                ev.ts, "MEDIUM", "registration_reject",
                f"registration reject/denial: {ev.detail}", ev.raw,
                ev.order))

    return collapse(anomalies)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def fmt(s: str, redact_on: bool, width: int = 100) -> str:
    s = sanitize(redact(s, redact_on))
    return s if len(s) <= width else s[: width - 3] + "..."


def print_human(p: Parsed, anomalies: list[Anomaly], redact_on: bool,
                timeline: bool) -> None:
    print("radio-triage")
    print(f"  log: {sanitize(p.path)}  sha256:{p.sha256[:16]}")
    print(f"  lines: {p.lines_total} total, {p.lines_matched} logcat-parsed,"
          f" {len(p.events)} telephony events")
    print(f"  redaction: {'ON (default; --no-redact to disable)' if redact_on else 'OFF'}")
    print()

    if not p.events:
        print("No telephony events recognized. If this log came from"
              " 'adb logcat -b radio', the buffer may have rotated —"
              " reproduce the issue and capture immediately after.")
        return

    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    if anomalies:
        print(f"ANOMALIES ({len(anomalies)}):")
        for a in sorted(anomalies, key=lambda a: (sev_order[a.severity],
                                                  a.ts)):
            print(f"  [{a.severity}] {a.ts}  {a.kind}: {a.summary}")
            print(f"      {fmt(a.raw, redact_on)}")
        print()
    else:
        print("No anomalies detected by current rules.")
        print()

    if timeline:
        print(f"TIMELINE ({len(p.events)} events):")
        for ev in p.events:
            print(f"  {ev.ts}  [{ev.kind}] {ev.detail}"
                  f"  ({sanitize(ev.tag)})")
        print()


def to_json(p: Parsed, anomalies: list[Anomaly], redact_on: bool) -> str:
    return json.dumps(
        {
            "log": {"path": sanitize(p.path), "sha256": p.sha256,
                    "lines_total": p.lines_total,
                    "lines_matched": p.lines_matched,
                    "events": len(p.events)},
            "redaction": redact_on,
            "anomalies": [
                {"ts": a.ts, "severity": a.severity, "kind": a.kind,
                 "summary": a.summary,
                 "raw": sanitize(redact(a.raw, redact_on))}
                for a in anomalies
            ],
            "timeline": [
                {"ts": e.ts, "kind": e.kind, "detail": e.detail,
                 "tag": sanitize(e.tag)}
                for e in p.events
            ],
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        prog="radio-triage",
        description="Triage Android radio logs: telephony timeline and"
                    " anomaly detection.")
    ap.add_argument("--log", required=True, help="radio logcat file")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--timeline", action="store_true",
                    help="print full event timeline")
    ap.add_argument("--no-redact", action="store_true",
                    help="disable default redaction of subscriber"
                         " identifiers in log excerpts")
    args = ap.parse_args()
    redact_on = not args.no_redact

    parsed = parse_log(args.log)
    anomalies = detect_anomalies(parsed)

    if args.json:
        print(to_json(parsed, anomalies, redact_on))
    else:
        print_human(parsed, anomalies, redact_on, args.timeline)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
