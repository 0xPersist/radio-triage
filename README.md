# radio-triage

Android radio log triage. Parses the radio logcat buffer into a telephony
event timeline and flags anomalies: service loss, RAT downgrades, IMS
deregistrations, registration flapping, and explicit reject causes.

Companion to [carrier-diff](https://github.com/0xPersist/carrier-diff):
carrier-diff answers "what state differs between profiles"; radio-triage
answers "what happened over time."

## Why

Telephony failures are usually diagnosed from a wall of radio log noise.
This tool extracts the registration/service events that matter and scores
the transitions. RAT downgrades toward the 2G family (GSM/GPRS/EDGE) are
weighted HIGH because forced downgrade is a classic cell-site-simulator
indicator; host-side logs alone cannot confirm that, so HIGH downgrade
findings should be verified with RF-side capture (e.g. Rayhunter).

## Usage

```
./capture-radio.sh baseline          # -> baseline-radio.txt
python3 radio_triage.py --log baseline-radio.txt
python3 radio_triage.py --log baseline-radio.txt --timeline
python3 radio_triage.py --log baseline-radio.txt --json
```

Or capture manually: `adb logcat -b radio -v threadtime -d > radio.txt`

## Detections

| Kind | Severity | Trigger |
|---|---|---|
| service_loss | HIGH | transition to OUT_OF_SERVICE / EMERGENCY_ONLY |
| rat_downgrade | HIGH if to 2G, else LOW | RAT rank decrease (NR>LTE>3G>2G) |
| ims_deregistration | MEDIUM | IMS deregistered (VoLTE/VoNR impact) |
| registration_flapping | MEDIUM | repeated service transitions in a short window |
| registration_reject | MEDIUM | reject/denial causes in registration messages |

## Security model

Log content is treated as untrusted input (network-side behavior influences
what the baseband logs). Concretely:

- Subscriber-identifying substrings (phone numbers, IMSI/ICCID/IMEI-shaped
  digit runs, labeled identifiers, cell identity fields) are redacted by
  default in all output as `[REDACTED:<hash8>]`; hashes preserve
  same/different semantics. `--no-redact` for local analysis only.
- All control characters are rendered as visible escapes (terminal escape
  injection defense).
- Raw log excerpts print only for anomalies (data minimization); the
  timeline shows normalized events, not message bodies.
- Input capped at 128 MiB and 500k events (crafted-input guards); SHA-256
  of the exact analyzed bytes stamped on every output.
- capture-radio.sh validates the label (path traversal guard) and writes
  captures with owner-only permissions.
- No network access, no subprocess execution, stdlib only. Python 3.8+.

Redaction is pattern-based and cannot guarantee unrecognized identifier
formats are caught. Review output before sharing regardless.

Covered: E.164 numbers with `+`; bare digit runs of 10-20 characters, which
spans national and country-code phone numbers, IMSI, IMEI and ICCID;
separator-formatted IMEI/IMSI (`35-209900-176148-1`, `35 209900 176148 1`);
labeled `imsi`/`iccid`/`imei`/`msisdn` identifiers; and cell identity fields
(`mCi`, `cellIdentity`, `ci`, `pci`, `tac`, `cid`, `lac`).

The 10-digit floor is a deliberate trade-off. It is what catches an ordinary
national number, and the cost is that any bare 10-digit or longer number is
hashed, including an epoch-second timestamp if a vendor log emits one. Logcat
threadtime stamps are date-formatted, not epoch, so timeline and anomaly
timestamps are unaffected; reject causes, MCC/MNC and other short numeric
fields stay readable. Runs of 9 digits or fewer are left alone.

A self-contained regression suite (`run_tests.py`, 37 checks across 11
groups) covers detection logic, redaction including the separator and
short-digit-run formats, over-redaction guards for fields that must stay
readable, escape injection, resource guards, hash integrity, the Python
version floor, reject calibration, and anomaly collapse.

## Limitations

- Detection rules are validated against synthetic logcat fixtures; radio
  log tag/message formats vary across OEMs and Android versions. Validate
  against your device and report drift (the lines-matched count in the
  header is the drift indicator).
- Transition lines are read rightmost-token-wins ("old -> new" semantics)
  and all state is tracked per phone/slot (phoneId/slotId hints, default
  phone 0), so recoveries are not misread as outages and multi-SIM logs do
  not fabricate cross-slot downgrades.
- Known minor limitations: logcat timestamps lack a year, so ordering
  across a year boundary is unreliable.
- Host-side logs show what the OS observed, not what the network did. RF
  conclusions (e.g. IMSI catcher presence) require RF-side evidence.

## License

MIT
