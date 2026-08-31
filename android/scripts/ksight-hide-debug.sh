#!/system/bin/sh
# Start a capture, hide USB debugging / developer options for its duration,
# then restore those settings even if adbd is killed.
#
# Usage: ksight-hide-debug.sh <duration-seconds> <capture-command...>

DURATION="$1"
shift
if [ -z "$DURATION" ] || [ "$#" -lt 1 ]; then
    echo "usage: ksight-hide-debug.sh <duration-seconds> <command...>" >&2
    exit 2
fi

KSIGHT_DIR=/data/local/tmp/ksight
LOG=$KSIGHT_DIR/capture-live.log
STATE=$KSIGHT_DIR/debug-restore.state
PIDFILE=$KSIGHT_DIR/capture.pid
WATCHDOG=$KSIGHT_DIR/restore-watchdog.pid
DUMP_READY=$KSIGHT_DIR/dump-ready

mkdir -p "$KSIGHT_DIR"
: > "$LOG"

adb_was=$(settings get global adb_enabled 2>/dev/null || echo 1)
dev_was=$(settings get global development_settings_enabled 2>/dev/null || echo 1)
wifi_was=$(settings get global adb_wifi_enabled 2>/dev/null || echo 0)
printf '%s\n%s\n%s\n' "$adb_was" "$dev_was" "$wifi_was" > "$STATE"

restore() {
    settings put global adb_enabled "${adb_was:-1}" >/dev/null 2>&1 || true
    settings put global adb_wifi_enabled "${wifi_was:-0}" >/dev/null 2>&1 || true
    settings put global development_settings_enabled "${dev_was:-1}" >/dev/null 2>&1 || true
}

WATCH_SECS=$((DURATION + 8))
if [ "$WATCH_SECS" -lt 10 ]; then
    WATCH_SECS=10
fi
(sleep "$WATCH_SECS"; restore) >/dev/null 2>&1 &
echo $! > "$WATCHDOG"

if command -v setsid >/dev/null 2>&1; then
    setsid "$@" >>"$LOG" 2>&1 &
else
    nohup "$@" >>"$LOG" 2>&1 &
fi
echo $! > "$PIDFILE"
CAP_PID=$(cat "$PIDFILE")

is_dump=0
case " $* " in
    *" dump-package "*) is_dump=1 ;;
esac

i=0
# Capture: wait for session=. Dump: wait for dump-ready (after ART attach, before launch).
# Do not treat leftover last_session as dump-ready or USB hide races launch.
max_i=200
while [ "$i" -lt "$max_i" ]; do
    if [ "$is_dump" = 1 ]; then
        if [ -f "$DUMP_READY" ]; then
            break
        fi
    else
        if grep -q 'session=' "$LOG" 2>/dev/null; then
            break
        fi
        if [ -s "$KSIGHT_DIR/spool/last_session" ]; then
            break
        fi
    fi
    if ! kill -0 "$CAP_PID" 2>/dev/null; then
        restore
        exit 1
    fi
    sleep 0.1
    i=$((i + 1))
done

settings put global adb_enabled 0 >/dev/null 2>&1 || true
settings put global adb_wifi_enabled 0 >/dev/null 2>&1 || true
settings put global development_settings_enabled 0 >/dev/null 2>&1 || true
exit 0
