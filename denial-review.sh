#!/system/bin/sh
# denial-review.sh -- one self-contained tool to review SELinux avc denials on
# THIS device and build a compile-checked vendor_sepolicy candidate (out.cil).
#
# It reads the live denials, drops the useless ones (property scans, DNS-proxy
# sockets, zygote probes, catch-all device/socket labels, hal_camera_default),
# de-duplicates against the vendor_sepolicy.cil already installed (so a rule is
# only suggested when it is NOT already there, directly or via an attribute),
# then builds out.cil = installed policy + approved rules and compiles it the
# exact way init does at boot. If that compile fails, init would fail too and
# the phone would drop to the bootloader, so out.cil is never installed
# automatically -- the script prints the commands for you to run yourself.
#
# Run on the phone as root (adb shell su, or Termux as root):
#
#   sh denial-review.sh                 # scan -> review files -> out.cil + check
#   sh denial-review.sh build           # rebuild out.cil after you edit the
#                                        # review files, then compile-check
#   sh denial-review.sh help
#
# Options (before the command):
#   -o "d1 d2"   only review these source domains (default: all in scope)
#   -x "d1 d2"   also exclude these source domains
#   -l N         property-scan threshold (default 20)
#
# Nothing is written to /vendor and the SELinux mode is never changed.

set -u

# ----------------------------------------------------------------- config ---
WORK=/data/local/tmp/seclic-review
SEL=/vendor/etc/selinux
SYS=/system/etc/selinux
VENDOR_CIL=$SEL/vendor_sepolicy.cil
SCAN_LIMIT=20
# Never review these (hal_camera is already handled; shell/su are our own
# debugging; untrusted/isolated/ephemeral are third-party app sandboxes).
EXCLUDE="hal_camera_default shell su"
EXCLUDE_RE="^(untrusted_app|isolated|ephemeral_app)"
ONLY=""                                  # set by -o to restrict scope
# Sources whose denials are ALWAYS surfaced -- their noise is shown in
# app-review.cil instead of being dropped (so you see every denial from them).
ALWAYS_RE="oplus"

die()  { echo "denial-review: $*" >&2; exit 1; }
info() { echo "denial-review: $*" >&2; }

# --------------------------------------------------------------- arg parse --
while getopts o:x:l:A: OPT 2>/dev/null; do
    case $OPT in
        o) ONLY=$OPTARG ;;
        x) EXCLUDE="$EXCLUDE $OPTARG" ;;
        l) SCAN_LIMIT=$OPTARG ;;
        A) ALWAYS_RE=$OPTARG ;;
        *) ;;
    esac
done
shift $((OPTIND - 1))
CMD=${1:-scan}

[ -r "$VENDOR_CIL" ] || die "cannot read $VENDOR_CIL (run on the phone as root)"
VER=$(tr -d ' \r\n' < "$SEL/plat_sepolicy_vers.txt" 2>/dev/null)
[ -n "$VER" ] || die "cannot read $SEL/plat_sepolicy_vers.txt"
VSUF="_$(echo "$VER" | tr '.' '_')"
mkdir -p "$WORK" || die "cannot create $WORK"

# The files init compiles together, used for name resolution + dedup coverage.
POLSET="$SYS/plat_sepolicy.cil $SYS/mapping/$VER.cil $SYS/mapping/$VER.compat.cil
/system_ext/etc/selinux/system_ext_sepolicy.cil /system_ext/etc/selinux/mapping/$VER.cil
/system_ext/etc/selinux/mapping/$VER.compat.cil
/product/etc/selinux/product_sepolicy.cil /product/etc/selinux/mapping/$VER.cil
$SEL/plat_pub_versioned.cil $VENDOR_CIL /odm/etc/selinux/odm_sepolicy.cil"

# ----------------------------------------------------------- compile check --
# Compile the full split policy exactly like init (system/core/init selinux.cpp)
# with $1 as the vendor policy. $2 = label for messages. Returns 0 on success.
compile_policy() {
    cand=$1; label=$2
    SECILC=$(command -v secilc 2>/dev/null); [ -n "$SECILC" ] || SECILC=/system/bin/secilc
    [ -x "$SECILC" ] || { echo "  secilc not found"; return 2; }
    set --
    for f in "$SYS/mapping/$VER.compat.cil" \
             /system_ext/etc/selinux/system_ext_sepolicy.cil /system_ext/etc/selinux/mapping/$VER.cil \
             /system_ext/etc/selinux/mapping/$VER.compat.cil \
             /product/etc/selinux/product_sepolicy.cil /product/etc/selinux/mapping/$VER.cil \
             "$SEL/plat_pub_versioned.cil" "$cand" /odm/etc/selinux/odm_sepolicy.cil; do
        [ -f "$f" ] && set -- "$@" "$f"
    done
    if [ -f "$SEL/genfs_labels_version.txt" ]; then
        G=$(tr -d ' \r\n' < "$SEL/genfs_labels_version.txt")
        [ "$G" -ge 202504 ] 2>/dev/null && [ -f "$SYS/plat_sepolicy_genfs_$G.cil" ] && set -- "$@" "$SYS/plat_sepolicy_genfs_$G.cil"
    fi
    "$SECILC" "$SYS/plat_sepolicy.cil" -m -M true -G -N -c 30 \
        "$SYS/mapping/$VER.cil" -o "$WORK/$label.policy" -f /dev/null "$@" \
        > "$WORK/$label.log" 2>&1
}

check_out() {
    echo "denial-review: compiling (init-identical, policy version 30) ..."
    if ! compile_policy "$VENDOR_CIL" baseline; then
        echo "denial-review: baseline FAILED -- the harness itself is wrong here, aborting."
        tail -n 12 "$WORK/baseline.log"; return 2
    fi
    echo "  baseline (current policy) ... PASS"
    if compile_policy "$WORK/out.cil" out; then
        echo "  candidate out.cil ........... PASS ($(wc -c < "$WORK/out.policy") bytes)"
        return 0
    fi
    echo "  candidate out.cil ........... FAIL -- do NOT install"
    tail -n 20 "$WORK/out.log"; return 1
}

# ---------------------------------------------------------------- classify --
# Reads the whole policy (pass 1) then the denial log (pass 2); writes the
# review files + report. The policy files are concatenated into one file so
# the FNR==NR "first file" test cleanly separates the two passes.
classify() {
    : > "$WORK/allpol.txt"
    for f in $POLSET; do [ -f "$f" ] && cat "$f" >> "$WORK/allpol.txt"; done
    awk -v VSUF="$VSUF" -v LIMIT="$SCAN_LIMIT" -v EXCL="$EXCLUDE" -v EXRE="$EXCLUDE_RE" -v ONLY="$ONLY" -v ALWAYS="$ALWAYS_RE" '
    BEGIN {
        split(EXCL, e, " "); for (i in e) EXC[e[i]] = 1
        non = split(ONLY, oo, " ")
    }
    # ---- pass 1: declarations, property types, existing allow rules (dedup) ----
    FNR == NR {
        line = $0; gsub(/[ \t]+/, " ", line)
        if (line ~ /^\(type /)               { split(line, w, " "); gsub(/[()]/, "", w[2]); DECL[w[2]] = 1 }
        else if (line ~ /^\(typeattribute /) { split(line, w, " "); gsub(/[()]/, "", w[2]); DECL[w[2]] = 1 }
        else if (line ~ /^\(typeattributeset property_type /) {
            t = line; gsub(/[()]/, " ", t); n = split(t, w, " ")
            for (i = 3; i <= n; i++) PROP[w[i]] = 1
        }
        else if (line ~ /^\(allow [^ ]+ [^ ]+ \([^ ]+ \([^()]*\)\)\)$/) {
            t = line; gsub(/[()]/, " ", t); n = split(t, w, " ")
            for (i = 5; i <= n; i++) COV[w[2] "/" w[3] "/" w[4] "/" w[i]] = 1
        }
        next
    }
    # ---- pass 2: collect denial groups ----
    {
        if (!match($0, /denied +\{[^}]*\}/)) next
        p = substr($0, RSTART, RLENGTH); sub(/^denied +\{ */, "", p); sub(/ *\}$/, "", p)
        if (!match($0, /scontext=[^ ]+/)) next; ns = split(substr($0, RSTART+9, RLENGTH-9), a, ":"); s = a[3]
        if (!match($0, /tcontext=[^ ]+/)) next; nt = split(substr($0, RSTART+9, RLENGTH-9), b, ":"); t = b[3]
        if (!match($0, /tclass=[^ ]+/)) next; c = substr($0, RSTART+7, RLENGTH-7); gsub(/[^a-z_0-9]/, "", c)
        # MLS mismatch: target carries categories the source lacks (s0 vs s0:c..).
        if (nt >= 5 && ns < 5) CATMISS[s] = 1
        if (c == "file" && isprop(t) && !((s "/" t) in SEENPT)) { SEENPT[s "/" t] = 1; NPROP[s]++ }
        np = split(p, pp, " ")
        for (i = 1; i <= np; i++) {
            k = s SUBSEP t SUBSEP c SUBSEP pp[i]
            if (!(k in D)) { D[k] = 1; ORD[++nd] = k }
        }
    }
    function isprop(x) { return (x in PROP) || x ~ /_prop$/ }
    function isapp(x)  { return x ~ /_app$/ || x ~ /_app_[0-9]+$/ || x ~ /^untrusted_app/ || x ~ /^isolated/ || x ~ /^ephemeral_app/ }
    function resolve(x) { if ((x VSUF) in DECL) return x VSUF; if (x in DECL) return x; return "" }
    function inscope(x,   i) {
        if (x in EXC) return 0
        if (EXRE != "" && x ~ EXRE) return 0
        if (non > 0) { for (i = 1; i <= non; i++) if (x == oo[i] || x ~ ("^" oo[i] "_[0-9]+$")) return 1; return 0 }
        return 1
    }
    # ---- decide ----
    END {
        for (j = 1; j <= nd; j++) {
            split(ORD[j], f, SUBSEP); s = f[1]; t = f[2]; c = f[3]; perm = f[4]
            scope = inscope(s)
            rs = resolve(s); rt = (s == t) ? "self" : resolve(t)
            if (rs == "" || rt == "") { if (scope) unres[(rs=="" ? s : t)]++; continue }
            # Already allowed by a type rule but still showing up = NOT a missing
            # allow. It is an MLS category or file-label constraint; record it so
            # it is visible, with the fix that actually applies.
            if ((rs "/" rt "/" c "/" perm) in COV || (rt == "self" && (rs "/self/" c "/" perm) in COV)) {
                if (scope) {
                    CON[rs SUBSEP rt SUBSEP c] = CON[rs SUBSEP rt SUBSEP c] " " perm; CSEEN[rs SUBSEP rt SUBSEP c] = 1; csrc[rs] = 1
                    if (CATMISS[s]) MLSFIX[rs] = 1     # blocked by MLS categories -> mlstrustedsubject fixes it
                }
                continue
            }

            key = rs SUBSEP rt SUBSEP c
            klass = "keep"
            if (c == "security" || perm ~ /^(execmem|execmod|execheap|execstack)$/ ||
                (c ~ /^cap/ && perm ~ /^(sys_module|mac_admin|mac_override)$/)) klass = "risky"
            else {
                reason = ""
                # Only a mass property scan is noise; reading a few specific
                # properties is a real need, so it is kept (reason stays "").
                if (c == "file" && isprop(t) && perm ~ /^(read|open|getattr|map)$/ && NPROP[s] > LIMIT)
                    reason = "property scan"
                else if (t == "zygote" && c == "unix_stream_socket" && perm == "getopt") reason = "zygote probe"
                else if (t == "socket_device" && c == "sock_file") reason = "app socket (dnsproxy etc)"
                else if ((t == "device" || t == "socket_device" || t == "unlabeled") && isapp(s)) reason = "catch-all label"
                if (reason != "") klass = "noise"
            }

            if (!scope) {
                O[key] = O[key] " " perm
                OWHY[key] = (klass == "keep") ? "ok" : (klass == "noise" ? ("noise: " reason) : "risky")
                OSEEN[key] = 1; osrc[s] = 1; continue
            }
            if (klass == "risky") { R[key] = R[key] " " perm; RSEEN[key] = 1; continue }
            if (klass == "noise") {
                # apps and always-surface sources (oplus) keep their noise
                # visible in app-review; everything else is just counted.
                if (isapp(s) || (ALWAYS != "" && s ~ ALWAYS)) { A[key] = A[key] " " perm; AWHY[key] = reason; ASEEN[key] = 1 }
                else drop[reason]++
                continue
            }
            K[key] = K[key] " " perm; KSEEN[key] = 1
        }

        kept = 0; nr = 0; na = 0; no = 0; nos = 0
        for (k in KSEEN) { split(k, g, SUBSEP); print "(allow " g[1] " " g[2] " (" g[3] " (" substr(K[k],2) ")))" > SUG; kept++ }
        for (k in RSEEN) { split(k, g, SUBSEP); print "(allow " g[1] " " g[2] " (" g[3] " (" substr(R[k],2) ")))" > RSK; nr++ }
        for (k in ASEEN) { split(k, g, SUBSEP); print ";; " AWHY[k] > APPF; print "(allow " g[1] " " g[2] " (" g[3] " (" substr(A[k],2) ")))" > APPF; na++ }
        print ";; Out-of-scope denials, tagged ok/noise/risky. Review before adding any." > OTHF
        for (k in OSEEN) { split(k, g, SUBSEP); print ";; " OWHY[k] > OTHF; print "(allow " g[1] " " g[2] " (" g[3] " (" substr(O[k],2) ")))" > OTHF; no++ }
        for (o in osrc) nos++
        nc = 0; ncs = 0
        print ";; These are ALREADY allowed by a type rule but keep getting denied." > CONF
        print ";; That means an MLS category or a wrong file label is blocking them," > CONF
        print ";; NOT a missing allow -- the (allow) lines below are already in your" > CONF
        print ";; policy and adding them again does nothing. Fix instead by either:" > CONF
        print ";;   - relabelling the target path in *_file_contexts, or" > CONF
        print ";;   - if this domain legitimately must cross app data categories," > CONF
        print ";;     making it mlstrustedsubject (RISKY -- it then ignores MLS)." > CONF
        for (k in CSEEN) { split(k, g, SUBSEP); print ";; recurring: " g[1] " -> " g[2] " " g[3] " {" substr(CON[k],2) "}" > CONF }
        for (k in CSEEN) nc++
        # Ready-to-apply MLS fix for sources blocked by category separation.
        nmls = 0
        print ";; mlstrustedsubject fix for sources blocked by MLS categories" > CONFIX
        print ";; (these were ALREADY type-allowed but denied because the target" > CONFIX
        print ";;  carried app categories the source lacked). Applying this lets the" > CONFIX
        print ";;  domain cross MLS categories -- correct for a vendor HAL that must" > CONFIX
        print ";;  read per-app data (adbd, dumpstate, bluetooth etc are the same)," > CONFIX
        print ";;  but it DOES weaken category separation, so review each line." > CONFIX
        for (o in MLSFIX) { print "(typeattributeset mlstrustedsubject (" o "))" > CONFIX; nmls++ }
        print "" > CONF; print ";; " nmls " source(s) are MLS-blocked; ready fix in constraint-fix.cil" > CONF
        for (o in csrc) ncs++

        print "scope: " (non > 0 ? ("only [" ONLY "]") : "all sources except excluded") > REP
        print "excluded: " EXCL "  and /" EXRE "/" > REP
        print "" > REP
        print "NEW rules (not already in your policy): " kept "  -> suggested.cil" > REP
        print "app denials to review (likely noise):   " na "  -> app-review.cil" > REP
        print "risky (never auto-added):               " nr "  -> risky.cil" > REP
        print "out-of-scope saved:                     " no " from " nos " sources -> other.cil" > REP
        print "already-allowed but STILL denied:       " nc " from " ncs " sources -> constraint.cil (MLS/label, not a missing allow)" > REP
        print "" > REP
        print "in-scope dropped:" > REP
        for (d in drop) printf "  %-26s %d\n", d, drop[d] > REP
        nu = 0; for (u in unres) nu++
        if (nu) { print "" > REP; print "unresolved in-scope types (fix the file label, not a rule): " nu > REP
                  for (u in unres) printf "  %-26s %d\n", u, unres[u] > REP }
    }
    ' "$WORK/allpol.txt" "$WORK/raw.txt" \
      SUG="$WORK/suggested.cil" RSK="$WORK/risky.cil" APPF="$WORK/app-review.cil" \
      OTHF="$WORK/other.cil" CONF="$WORK/constraint.cil" CONFIX="$WORK/constraint-fix.cil" REP="$WORK/report.txt"
}

# ----------------------------------------------------------- build out.cil --
# out.cil = installed policy + suggested.cil + any extra files passed in
# (e.g. constraint-fix.cil for the MLS mlstrustedsubject fix).
build_out() {
    [ -s "$WORK/suggested.cil" ] || { : > "$WORK/suggested.cil"; }
    cp "$VENDOR_CIL" "$WORK/out.cil" || die "cannot read $VENDOR_CIL"
    echo "" >> "$WORK/out.cil"
    echo ";; ---- reviewed rules added $(date) ----" >> "$WORK/out.cil"
    nnew=0
    for src in "$WORK/suggested.cil" "$@"; do
        [ -s "$src" ] || continue
        n=$(grep -cE '^\((allow|typeattributeset|allowx|typetransition)' "$src" 2>/dev/null) || n=0
        [ "$n" -gt 0 ] || continue
        echo ";; from $(basename "$src"):" >> "$WORK/out.cil"
        grep -E '^\((allow|typeattributeset|allowx|typetransition)' "$src" >> "$WORK/out.cil"
        nnew=$((nnew + n))
    done
    info "out.cil = your policy + $nnew reviewed rule(s)${*:+ (incl $*)}"
}

install_hint() {
    echo
    echo "out.cil is NOT installed. Back up, install, reboot -- yourself:"
    echo "    cp $VENDOR_CIL $WORK/vendor_sepolicy.backup.cil"
    echo "    mount -o rw,remount /vendor"
    echo "    cp $WORK/out.cil $VENDOR_CIL"
    echo "    chmod 644 $VENDOR_CIL"
    echo "    chcon u:object_r:vendor_configs_file:s0 $VENDOR_CIL"
    echo "    sync; reboot"
    echo "To revert: cp $WORK/vendor_sepolicy.backup.cil $VENDOR_CIL (then chcon + reboot)"
}

# ----------------------------------------------------------------- main -----
case "$CMD" in
    scan)
        info "collecting denials (logcat + dmesg) ..."
        { logcat -d -b all 2>/dev/null; dmesg 2>/dev/null; } | grep 'avc: *denied' > "$WORK/raw.txt"
        info "$(wc -l < "$WORK/raw.txt") denial lines"
        classify
        for f in suggested risky app-review other constraint constraint-fix; do [ -f "$WORK/$f.cil" ] || : > "$WORK/$f.cil"; done
        echo; cat "$WORK/report.txt"; echo
        echo "===================== NEW RULES (review!) ====================="
        cat "$WORK/suggested.cil"; [ -s "$WORK/suggested.cil" ] || echo "(none -- everything is already in your policy or was noise)"
        echo "=============================================================="
        build_out
        check_out && install_hint
        echo
        echo "Edit $WORK/suggested.cil, then rebuild:            sh $0 build"
        echo "To also apply the MLS fix (constraint-fix.cil):   sh $0 build $WORK/constraint-fix.cil"
        ;;
    build)
        [ -f "$WORK/suggested.cil" ] || die "no $WORK/suggested.cil -- run 'scan' first"
        shift 2>/dev/null || true
        build_out "$@"
        check_out && install_hint
        ;;
    help|-h|--help)
        sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
        ;;
    *)
        die "unknown command '$CMD' (use: scan | build | help)"
        ;;
esac
