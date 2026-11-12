#!/system/bin/sh
# On-device recovery. Run from any shell-uid context (adb shell, Shizuku,
# Termux+adb) when the device has rebooted and root is gone.
#
# Requires the payload already in /data/local/tmp: gl_root, ksu_ctrl.ko,
# ksud, ksu_loader.sh.
set -u
D=${RUNDIR:-/data/local/tmp}

echo '[*] checking current state...'
if [ "$($D/kbin/su -c 'id -u' 2>/dev/null)" = "0" ]; then
  echo '[+] KernelSU already running, nothing to do'
  exit 0
fi

echo '[*] clearing stale runtime files'
rm -f "$D/gl_root_proof" "$D/ksu_port.log"

echo '[*] starting exploit (the window is ~1 min after boot)'
cd "$D" || exit 1
nohup env SYSCTL_WALK_ATTEMPTS=20 KSU_LOADER=1 KSU_RUNDIR="$D" ./gl_root > gl_run.log 2>&1 &

i=0
while [ $i -lt 40 ]; do
  sleep 5
  i=$((i+1))
  if [ -f "$D/ksu_port.log" ] && grep -q 'throne: .*Crowning' "$D/ksu_port.log" 2>/dev/null; then
    echo '[+] module loaded and Manager recognised'
    break
  fi
  grep -q 'no usable mapping' "$D/gl_run.log" 2>/dev/null && {
    echo '[!] exploit failed: device has been up too long, reboot and retry within 1 min'
    exit 1
  }
  grep -q 'insmod rc=1' "$D/ksu_port.log" 2>/dev/null && {
    echo '[!] insmod failed: ksu_ctrl.ko looks corrupt, re-push it'
    exit 1
  }
done

uid=$($D/kbin/su -c 'id -u' 2>/dev/null)
if [ "$uid" = "0" ]; then
  echo
  echo '[+] done. root available:'
  echo "    $D/kbin/su -c \"command\""
  exit 0
fi
echo "[!] not ready (su -> $uid)"
echo '    log: tail -20 /data/local/tmp/gl_run.log'
exit 1
