#!/system/bin/sh
# KernelSU / Magisk late-start service for Dev Root collectors.
# This is a development-stage boot helper, not AOSP init + SELinux.

MODDIR="${0%/*}"
KSIGHT_DIR="/data/local/tmp/ksight"
CONFIG="${KSIGHT_DIR}/ksightd.json"
AGENT="${KSIGHT_DIR}/ksightd"
LOG="${KSIGHT_DIR}/ksightd.log"
LOCK="${KSIGHT_DIR}/ksightd.lock"
DISABLED="${KSIGHT_DIR}/ksightd.disabled"

wait_for_data() {
  i=0
  while [ "$i" -lt 30 ]; do
    if [ -d /data/local/tmp ] && [ -f "$AGENT" ] && [ -f "$CONFIG" ]; then
      return 0
    fi
    i=$((i + 1))
    sleep 2
  done
  return 1
}

collector_running() {
  if [ -f "$LOCK" ]; then
    pid=$(tr -d ' \n' <"$LOCK" 2>/dev/null)
    if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ]; then
      cmdline=$(tr '\000' ' ' <"/proc/$pid/cmdline" 2>/dev/null)
      case "$cmdline" in
        *ksightd*run*) return 0 ;;
      esac
    fi
    rm -f "$LOCK"
  fi
  return 1
}

start_collector() {
  mkdir -p "$KSIGHT_DIR"
  "$AGENT" run --config "$CONFIG" --dry-run >/dev/null 2>&1 || return 1
  "$AGENT" run --config "$CONFIG" >>"$LOG" 2>&1
}

wait_for_data || exit 0
backoff=1
while true; do
  if [ -f "$DISABLED" ]; then
    sleep 5
    backoff=1
    continue
  fi
  if collector_running; then
    sleep 5
    continue
  fi
  started=$(date +%s 2>/dev/null || echo 0)
  start_collector
  stopped=$(date +%s 2>/dev/null || echo 0)
  lived=$((stopped - started))
  if [ "$lived" -ge 60 ]; then
    backoff=1
  fi
  sleep "$backoff"
  backoff=$((backoff * 2))
  if [ "$backoff" -gt 60 ]; then
    backoff=60
  fi
done
