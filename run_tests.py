#!/usr/bin/env python3
"""Self-contained regression + adversarial suite for radio-triage."""
from __future__ import annotations
import json, os, subprocess, sys, tempfile, time

# All fixtures live in a self-cleaning temp dir; the suite must not litter
# the invoking directory (and fake identifiers in fixtures must not be
# mistaken for real data).
_TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "radio_triage.py")
_TMP = tempfile.TemporaryDirectory(prefix="radio-triage-tests-")
os.chdir(_TMP.name)

PASS, FAIL = [], []
def run(args, timeout=30):
    return subprocess.run([sys.executable, _TOOL] + args,
                          capture_output=True, text=True, timeout=timeout)
def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  {detail}" if detail and not cond else ""))

L = "08-08 12:{m:02d}:{s:02d}.000  1000  2000 D "

def LT(sec, mon=8, day=8, year=None):
    """A threadtime prefix `sec` seconds past 12:00:00 on mon/day."""
    h, rem = divmod(sec, 3600)
    mi, ss = divmod(rem, 60)
    pre = f"{year:04d}-" if year is not None else ""
    return f"{pre}{mon:02d}-{day:02d} {12+h:02d}:{mi:02d}:{ss:02d}.000  1000  2000 D "

def flap_fixture(name, offsets, routine_between=False, mon=8, day=8):
    """Alternating service states at the given second offsets. The first is
    the baseline, so len(offsets)-1 transitions are recorded."""
    out = []
    for i, off in enumerate(offsets):
        st = "IN_SERVICE" if i % 2 == 0 else "OUT_OF_SERVICE"
        out.append(LT(off, mon, day) + f"SST: ServiceState changed {st}")
        if routine_between and i < len(offsets) - 1:
            out.append(LT(off + 1, mon, day) + "SIMRecords: SIM_STATE ready")
    open(name, "w").write("\n".join(out) + "\n")
    return name

# T1: functional — downgrade chain NR->LTE->GSM, service loss, IMS dereg, reject
fx = "\n".join([
    L.format(m=0,s=1)+"ServiceStateTracker: ServiceState changed IN_SERVICE rat=NR",
    L.format(m=0,s=5)+"ServiceStateTracker: RegState update rat=LTE IN_SERVICE",
    L.format(m=0,s=9)+"ServiceStateTracker: RegState update rat=GSM IN_SERVICE",
    L.format(m=1,s=2)+"ServiceStateTracker: ServiceState changed OUT_OF_SERVICE",
    L.format(m=1,s=9)+"ImsService: ims deregistered cause=NETWORK_LOST",
    L.format(m=2,s=3)+"RILJ: registration denied rejectCause=15",
    ""])
open("t1.txt","w").write(fx)
print("T1: functional detection")
out = run(["--log","t1.txt","--timeline"]).stdout
check("NR->LTE downgrade flagged LOW", "rat_downgrade" in out and "NR -> LTE" in out)
check("LTE->GSM flagged HIGH with 2G note", "LTE -> GSM" in out and "cell-site-simulator" in out)
check("service loss HIGH", "service_loss" in out and "OUT_OF_SERVICE" in out)
check("IMS deregistration flagged", "ims_deregistration" in out)
check("reject cause flagged", "registration_reject" in out)
check("timeline printed", "TIMELINE" in out)

# T2: redaction — phone number, IMSI-run, cell identity in raw excerpts
fx2 = "\n".join([
    L.format(m=0,s=1)+"RILJ: dial +14075551234 OUT_OF_SERVICE",
    L.format(m=0,s=2)+"ServiceStateTracker: IN_SERVICE imsi=310260123456789",
    L.format(m=0,s=3)+"ServiceStateTracker: OUT_OF_SERVICE cellIdentity ci=98765432 tac=1234",
    ""])
open("t2.txt","w").write(fx2)
print("T2: redaction")
out = run(["--log","t2.txt"]).stdout
jout = run(["--log","t2.txt","--json"]).stdout
check("phone number redacted", "+14075551234" not in out and "+14075551234" not in jout)
check("imsi redacted", "310260123456789" not in out and "310260123456789" not in jout)
check("cell id redacted", "98765432" not in out and "98765432" not in jout)
# note: raw excerpts print only for anomalies (data minimization); the
# revealing assertion targets the anomaly line's identifiers.
check("--no-redact reveals locally", "98765432" in run(["--log","t2.txt","--no-redact"]).stdout)

# T2b: RT-001 regression — formats that previously slipped past redaction.
# Each identifier rides on the OUT_OF_SERVICE line so it reaches an anomaly
# raw excerpt; raw excerpts print only for anomalies, so an identifier on an
# unparsed line would give a false pass.
print("T2b: redaction coverage (RT-001)")
_leakers = [
    ("10-digit national", "4075551234",         "dial 4075551234"),
    ("11-digit, no plus", "14075551234",        "dial 14075551234"),
    ("dash-formatted IMEI", "35-209900-176148-1", "imei 35-209900-176148-1"),
    ("space-formatted IMEI", "35 209900 176148 1", "imei 35 209900 176148 1"),
]
for _label, _ident, _payload in _leakers:
    _fn = "t2b_" + _label.replace(" ", "_").replace("-", "_") + ".txt"
    open(_fn, "w").write("\n".join([
        L.format(m=0, s=1) + "ServiceStateTracker: IN_SERVICE",
        L.format(m=0, s=2) + f"ServiceStateTracker: OUT_OF_SERVICE {_payload}",
    ]) + "\n")
    _plain = run(["--log", _fn]).stdout
    _raw = run(["--log", _fn, "--no-redact"]).stdout
    check(f"{_label}: reaches the excerpt at all", _ident in _raw)
    check(f"{_label}: redacted by default", _ident not in _plain)

# Over-redaction guard: numeric fields that must stay readable.
open("t2c.txt", "w").write("\n".join([
    L.format(m=0, s=1) + "ServiceStateTracker: IN_SERVICE",
    L.format(m=0, s=2) + "ServiceStateTracker: OUT_OF_SERVICE rejectCause=17 mcc=310 mnc=260",
]) + "\n")
_out2c = run(["--log", "t2c.txt"]).stdout
check("reject cause stays readable", "rejectCause=17" in _out2c)
check("mcc/mnc stay readable", "mcc=310" in _out2c and "mnc=260" in _out2c)
check("logcat timestamps not redacted", L.format(m=0, s=2).strip().split()[0] + " 12:00:02.000" in _out2c or "12:00:02.000" in _out2c)

# T3: escape injection in log message
# plant the escape payload on the line that BECOMES the anomaly excerpt
open("t3.txt","w").write(L.format(m=0,s=1)+"Evil: IN_SERVICE ok\n"
                         + L.format(m=0,s=2)+"Evil: OUT_OF_SERVICE \x1b[2J\x1b[8mHIDDEN\x07\n")
print("T3: escape injection")
r = run(["--log","t3.txt"])
check("no raw ESC in output", "\x1b" not in r.stdout and "\\x1b" in r.stdout)

# T4: resource guards — event bomb within size cap
print("T4: crafted-input guards")
bomb = (L.format(m=0,s=1)+"X: OUT_OF_SERVICE IN_SERVICE\n") * 600000
open("t4.txt","w").write(bomb)
r = run(["--log","t4.txt"], timeout=120)
check("event cap fired", r.returncode != 0 and "crafted-input guard" in (r.stderr+r.stdout))
r = run(["--log","missing.txt"])
check("missing file clean error", r.returncode != 0 and "Traceback" not in r.stderr)

# T5: hash integrity + json validity
print("T5: integrity + json")
import hashlib
expected = hashlib.sha256(open("t1.txt","rb").read()).hexdigest()
j = json.loads(run(["--log","t1.txt","--json"]).stdout)
check("sha256 matches input bytes", j["log"]["sha256"] == expected)
check("json anomalies structured", any(a["kind"]=="rat_downgrade" for a in j["anomalies"]))

# T6: flapping detector
print("T6: registration flapping")
lines=[]
states=["IN_SERVICE","OUT_OF_SERVICE"]*4
for i,st in enumerate(states):
    lines.append(L.format(m=3,s=i)+f"ServiceStateTracker: ServiceState changed {st}")
open("t6.txt","w").write("\n".join(lines)+"\n")
out = run(["--log","t6.txt"]).stdout
check("flapping flagged", "registration_flapping" in out)

# T6b: the flap window is elapsed time, not event count
print("T6b: flap window measured in seconds")
# four transitions inside 60 s -> flapping
out = run(["--log", flap_fixture("t6b1.txt", [0, 10, 30, 45, 60])]).stdout
check("4 transitions in 60 s -> flapping", "registration_flapping" in out)
check("summary states the window in seconds", "within 120 s" in out)
# four transitions spread over 10 minutes with only routine events between.
# This is the case the old event-count window got wrong: the transitions sit
# within 12 events of each other, but nowhere near 120 seconds apart.
out = run(["--log", flap_fixture("t6b2.txt", [0, 150, 300, 450, 600],
                                 routine_between=True)]).stdout
check("4 transitions over 10 min -> NOT flapping",
      "registration_flapping" not in out)
# boundary: first-to-last span of 119 s vs 121 s
out = run(["--log", flap_fixture("t6b3.txt", [0, 1, 40, 80, 120])]).stdout
check("4 transitions spanning 119 s -> flapping", "registration_flapping" in out)
out = run(["--log", flap_fixture("t6b4.txt", [0, 1, 40, 80, 122])]).stdout
check("4 transitions spanning 121 s -> NOT flapping",
      "registration_flapping" not in out)

# T7: python floor — no 3.10-only syntax at import time
print("T7: version floor")
import ast
tree = ast.parse(open(_TOOL).read())
has_future = any(isinstance(n, ast.ImportFrom) and n.module=="__future__" for n in ast.walk(tree))
check("__future__ annotations present", has_future)

# T8: audit regressions (M1 M2 M3 L1)
print("T8: audit regressions")
# M1: recovery line must NOT be a service_loss; outage transition line must be
fx8 = "\n".join([
    L.format(m=5,s=1)+"SST: ServiceState changed IN_SERVICE",
    L.format(m=5,s=2)+"SST: ServiceState changed IN_SERVICE -> OUT_OF_SERVICE",
    L.format(m=5,s=3)+"SST: ServiceState changed OUT_OF_SERVICE -> IN_SERVICE",
    ""])
open("t8a.txt","w").write(fx8)
out = run(["--log","t8a.txt"]).stdout
check("M1: outage transition flagged once", out.count("service_loss") == 1)
check("M1: recovery line not misread as loss", "IN_SERVICE -> OUT_OF_SERVICE" in out)
# M2: single-line RAT transition detected immediately
fx8b = "\n".join([
    L.format(m=6,s=1)+"SST: RegState rat=LTE IN_SERVICE",
    L.format(m=6,s=2)+"SST: RegState rat change LTE -> GSM rat=GSM",
    ""])
open("t8b.txt","w").write(fx8b)
out = run(["--log","t8b.txt"]).stdout
check("M2: single-line downgrade detected", "LTE -> GSM" in out and "rat_downgrade" in out)
# M3: interleaved phones must not fabricate a downgrade
fx8c = "\n".join([
    L.format(m=7,s=1)+"SST: RegState phoneId=0 rat=NR IN_SERVICE",
    L.format(m=7,s=2)+"SST: RegState phoneId=1 rat=LTE IN_SERVICE",
    L.format(m=7,s=3)+"SST: RegState phoneId=0 rat=NR IN_SERVICE",
    ""])
open("t8c.txt","w").write(fx8c)
out = run(["--log","t8c.txt"]).stdout
check("M3: no cross-phone false downgrade", "rat_downgrade" not in out)
# L1: 'notification' must not suppress IMS registered
fx8d = L.format(m=8,s=1)+"ImsService: ims registered notification sent\n"
open("t8d.txt","w").write(fx8d)
r = run(["--log","t8d.txt","--json"]).stdout
j = json.loads(r)
check("L1: registered-notification classified", any(e["kind"]=="ims" and e["detail"]=="REGISTERED" for e in j["timeline"]))

# T9: reject calibration (live-validation finding: rejectCause=0 is routine)
print("T9: reject calibration")
fx9 = "\n".join([
    L.format(m=9,s=1)+"SST: Broadcasting ServiceState NetworkRegistrationInfo rejectCause=0 regState=HOME IN_SERVICE",
    L.format(m=9,s=2)+"SST: Broadcasting ServiceState NetworkRegistrationInfo rejectCause=0 regState=HOME IN_SERVICE",
    L.format(m=9,s=3)+"RILJ: registration rejectCause=15 IN_SERVICE",
    ""])
open("t9.txt","w").write(fx9)
out = run(["--log","t9.txt"]).stdout
check("rejectCause=0 ignored", out.count("registration_reject") == 1)
check("nonzero cause still fires", "rejectCause=15" in out)

# T9b: every all-zero cause value is benign, not just a single "0"
print("T9b: all-zero reject causes")
fx9b = "\n".join([
    LT(1) + "RILJ: registration rejectCause=0 IN_SERVICE",
    LT(2) + "RILJ: registration failCause=00 IN_SERVICE",
    LT(3) + "RILJ: registration denyCause: 000 IN_SERVICE",
    LT(4) + "RILJ: registration rejectCause=17 IN_SERVICE",
    LT(5) + "RILJ: registration rejectCause=01 IN_SERVICE",
    ""])
open("t9b.txt", "w").write(fx9b)
out = run(["--log", "t9b.txt"]).stdout
check("rejectCause=0 ignored", "rejectCause=0 " not in out and "rejectCause=0\n" not in out)
check("failCause=00 ignored", "failCause=00" not in out)
check("denyCause: 000 ignored", "denyCause: 000" not in out)
check("rejectCause=17 still fires", "rejectCause=17" in out)
# a leading zero is not an all-zero value: 01 is cause 1 and must still fire
check("rejectCause=01 still fires", "rejectCause=01" in out)
check("exactly two rejects flagged", out.count("registration_reject") == 2)

# T10: identical-anomaly collapse
print("T10: anomaly collapse")
lines = []
for i in range(6):
    lines.append(L.format(m=10,s=2*i)+"SST: RegState rat=NR IN_SERVICE phoneId=0")
    lines.append(L.format(m=10,s=2*i+1)+"SST: RegState rat=LTE IN_SERVICE phoneId=0")
open("t10.txt","w").write("\n".join(lines)+"\n")
out = run(["--log","t10.txt"]).stdout
check("repeated downgrades collapsed to one line", out.count("rat_downgrade") == 1 and "[x" in out)
# T10b: interleaved phone0/phone1 downgrades collapse to exactly two groups
lines = []
for i in range(4):
    lines.append(L.format(m=11,s=4*i)+"SST: RegState rat=NR IN_SERVICE phoneId=0")
    lines.append(L.format(m=11,s=4*i+1)+"SST: RegState rat=LTE IN_SERVICE phoneId=0")
    lines.append(L.format(m=11,s=4*i+2)+"SST: RegState rat=NR IN_SERVICE phoneId=1")
    lines.append(L.format(m=11,s=4*i+3)+"SST: RegState rat=LTE IN_SERVICE phoneId=1")
open("t10b.txt","w").write("\n".join(lines)+"\n")
out = run(["--log","t10b.txt"]).stdout
check("interleaved phones collapse to two groups",
      out.count("rat_downgrade") == 2 and out.count("[x4") == 2)

# T11: year boundary — logcat omits the year, so Jan sorts before Dec
print("T11: year-boundary ordering")
P = "  1000  2000 D "
def wrap_lines(yr_dec=None, yr_jan=None):
    d = f"{yr_dec:04d}-" if yr_dec else ""
    j = f"{yr_jan:04d}-" if yr_jan else ""
    return [
        f"{d}12-31 23:58:00.000{P}SST: ServiceState changed IN_SERVICE rat=LTE RegState",
        f"{d}12-31 23:59:00.000{P}SST: ServiceState changed OUT_OF_SERVICE",
        f"{j}01-01 00:01:00.000{P}SST: RegState rat=GSM IN_SERVICE",
    ]

open("t11a.txt", "w").write("\n".join(wrap_lines()) + "\n")
out = run(["--log", "t11a.txt"]).stdout
check("wrap: both anomalies found",
      "service_loss" in out and "rat_downgrade" in out)
# the December outage must print before the January downgrade; on the raw
# string "01-01" sorts ahead of "12-31", which is the bug
check("wrap: Dec outage ordered before Jan downgrade",
      out.index("service_loss") < out.index("rat_downgrade"))

# the wrap must not read as a 120-second window: two transitions late on
# Dec 31 and two early on Jan 01, two hours apart in real time
open("t11b.txt", "w").write("\n".join([
    f"12-31 23:00:00.000{P}SST: ServiceState changed IN_SERVICE",
    f"12-31 23:00:30.000{P}SST: ServiceState changed OUT_OF_SERVICE",
    f"12-31 23:01:00.000{P}SST: ServiceState changed IN_SERVICE",
    f"01-01 01:00:00.000{P}SST: ServiceState changed OUT_OF_SERVICE",
    f"01-01 01:00:30.000{P}SST: ServiceState changed IN_SERVICE",
]) + "\n")
out = run(["--log", "t11b.txt"]).stdout
check("wrap: not treated as a 120-second flap window",
      "registration_flapping" not in out)

# explicit years (logcat -v year) parse and give the same anomalies
open("t11c.txt", "w").write("\n".join(wrap_lines(2026, 2027)) + "\n")
ja = json.loads(run(["--log", "t11a.txt", "--json"]).stdout)
jc = json.loads(run(["--log", "t11c.txt", "--json"]).stdout)
check("explicit year: lines parse", jc["log"]["lines_matched"] == 3)
sig = lambda j: [(a["kind"], a["severity"], a["summary"]) for a in j["anomalies"]]
check("explicit year: identical anomalies to inferred", sig(ja) == sig(jc))
check("explicit year: ordering preserved",
      [a["ts"] for a in jc["anomalies"]][0].startswith("2026-"))

# hashing is over the input bytes and is untouched by stamp parsing
check("explicit year: sha256 still over exact input bytes",
      jc["log"]["sha256"] == hashlib.sha256(open("t11c.txt", "rb").read()).hexdigest())

# T12: February length when the year is unknown
print("T12: February length inference")
def feb_fixture(name, yr=None, with_feb29=False):
    """Four service transitions spanning Feb 28 23:59:00 -> Mar 1 00:00:30,
    70 real seconds apart in a common year."""
    y = f"{yr:04d}-" if yr else ""
    rows = [
        (f"{y}02-28 23:59:00.000", "SST: ServiceState changed IN_SERVICE"),
        (f"{y}02-28 23:59:20.000", "SST: ServiceState changed OUT_OF_SERVICE"),
        (f"{y}02-28 23:59:40.000", "SST: ServiceState changed IN_SERVICE"),
    ]
    if with_feb29:
        # evidence of a leap year, on a line that produces no anomaly
        rows.append((f"{y}02-29 12:00:00.000", "SIMRecords: SIM_STATE ready"))
    rows += [
        (f"{y}03-01 00:00:10.000", "SST: ServiceState changed OUT_OF_SERVICE"),
        (f"{y}03-01 00:00:30.000", "SST: ServiceState changed IN_SERVICE"),
    ]
    open(name, "w").write("\n".join(f"{t}{P}{m}" for t, m in rows) + "\n")
    return name

# no 02-29 anywhere: February is 28 days, so the midnight is a 70-second step
out = run(["--log", feb_fixture("t12a.txt")]).stdout
check("Feb 28 -> Mar 1 with no 02-29: flapping flagged",
      "registration_flapping" in out)
# a 02-29 stamp proves a leap year: Feb 29 sits between, so these are a day apart
out = run(["--log", feb_fixture("t12b.txt", with_feb29=True)]).stdout
check("Feb 28 -> Mar 1 with a 02-29 present: NOT flapping",
      "registration_flapping" not in out)
# an explicit year needs no guessing at all — the real calendar decides
out = run(["--log", feb_fixture("t12c.txt", yr=2027)]).stdout
check("explicit common year 2027: flapping flagged",
      "registration_flapping" in out)
out = run(["--log", feb_fixture("t12d.txt", yr=2028)]).stdout
check("explicit leap year 2028: NOT flapping",
      "registration_flapping" not in out)

print()
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL: print("FAILED:", FAIL); sys.exit(1)
