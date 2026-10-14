# seclic-oplus-denial-addresser

On-device SELinux **denial addresser** for Android, aimed at ported ROMs
(OnePlus / oplus). It reads the live `avc: denied` log on the phone, keeps the
denials that are **real and missing**, drops the useless ones, and builds a
compile-checked `vendor_sepolicy.cil` candidate (`out.cil`) that you install
yourself. It never writes `/vendor` and never changes the SELinux mode.

A `vendor_sepolicy.cil` that fails to compile makes `init` abort at boot and
the phone drops to the bootloader, so `out.cil` is always compiled the exact
way `init` does **before** you flash it.

Companion to [seclic](https://github.com/nischay12089/seclic) (which merges
whole vendor policies). This tool is only about addressing denials.

## What it does

A single `scan`:

1. Collects denials (`logcat -b all` + `dmesg`).
2. **De-duplicates against the installed `vendor_sepolicy.cil`** — a rule is
   only suggested if it is not already granted, directly or through an
   attribute.
3. Classifies every denial and sorts it into one of these files in
   `/data/local/tmp/seclic-review/`:

   | File | What it holds |
   |---|---|
   | `suggested.cil` | real, missing rules — safe to install |
   | `app-review.cil` | app / oplus-source noise (sockets, probes, property reads) — visible so you decide |
   | `constraint.cil` | **already allowed but still denied** → an MLS category or file-label problem, not a missing allow |
   | `risky.cil` | SELinux-weakening denials (setenforce, execmem…) — never auto-added |
   | `other.cil` | out-of-scope sources (third-party apps, unrelated daemons), tagged |
4. Builds `out.cil` = installed policy + the approved rules.
5. Compiles `out.cil` like `init` (built in — no external tool). Prints PASS/FAIL.
6. Prints the backup / install / reboot commands for you to run.

## Why "useless denials" are filtered

Granting noise changes behaviour: code that used to be denied a property read
suddenly sees a value and takes a different, device-specific path — this is how
blanket rules break a ported camera or face unlock. So:

- A **mass property scan** (one source reading more than ~20 different
  properties) is noise.
- Reading a **few specific** properties is real and kept.
- DNS-proxy sockets (`socket_device`), zygote USAP probes, and catch-all
  `device` / `unlabeled` targets for apps are noise.
- `hal_camera_default` and third-party app sandboxes are out of scope by default.

### oplus apps and services

Every source matching `oplus` is **always surfaced** — real denials in
`suggested.cil`, noise in `app-review.cil`, MLS/label cases in `constraint.cil`
— so no oplus app or service denial is silently dropped.

## Usage

Run on the phone as root (adb shell su, or Termux as root):

```sh
adb push denial-review.sh /data/local/tmp/denial-review.sh
adb shell su -c "sh /data/local/tmp/denial-review.sh scan"
# review/trim /data/local/tmp/seclic-review/suggested.cil, then:
adb shell su -c "sh /data/local/tmp/denial-review.sh build"
```

When it reports `out.cil ... PASS`, it prints the exact commands to back up,
install and reboot. Example install (run them yourself):

```sh
cp /vendor/etc/selinux/vendor_sepolicy.cil /data/local/tmp/seclic-review/vendor_sepolicy.backup.cil
mount -o rw,remount /vendor
cp /data/local/tmp/seclic-review/out.cil /vendor/etc/selinux/vendor_sepolicy.cil
chmod 644 /vendor/etc/selinux/vendor_sepolicy.cil
chcon u:object_r:vendor_configs_file:s0 /vendor/etc/selinux/vendor_sepolicy.cil
sync; reboot
```

## Options

Put these before `scan` / `build`:

| Option | Meaning |
|---|---|
| `-o "d1 d2"` | review only these source domains |
| `-x "d1 d2"` | exclude extra source domains |
| `-A "regex"` | always-surface pattern (default `oplus`) |
| `-l N` | property-scan threshold (default 20) |

## Reading the results

- Install from `suggested.cil` (trim first if you like). Those are the only
  rules that go into `out.cil`.
- `constraint.cil` denials are **not fixed by an allow** — your policy already
  allows the type. Fix them by relabelling the target in `*_file_contexts`, or,
  only if the domain must cross app MLS categories, by making it
  `mlstrustedsubject` (the script writes that line commented out, because it
  weakens MLS separation).
- A service running with **no denials** (common for gameopt) means SELinux is
  not its problem; look at the service's own logs.

Note: the kernel audit subsystem rate-limits AVC messages (often 5/sec) and
drops the rest, mostly during the boot flood, so a single scan can miss some
denials. Trigger the feature you care about, then scan.

## Requirements

POSIX `sh`, `awk`, `grep`, `secilc` — all present on any rooted Android device
(toybox + one-true-awk work). No PC-side dependencies; it runs entirely on the
phone.

## Disclaimer

Flashing a modified `vendor_sepolicy.cil` can leave a device unbootable. The
compile check removes the most common cause (a policy that does not compile),
not every risk. Keep the backup the script makes; you are responsible for what
you install.

## License

MIT, see [LICENSE](LICENSE).
