#!/system/bin/sh
# Root-side loader, executed BY the exploit after it gains uid 0.
#
# The exploit fork runs this when KSU_LOADER=1 is set, as root, in the shell
# domain. It must finish inside the same boot as the exploit: a reboot drops
# the cred swap and undoes everything here.
#
# Expects (pushed beforehand):
#   /data/local/tmp/ksu_ctrl.ko    kernelsu.ko + fix-versions.py applied
#   /data/adb/ksud                 userspace daemon (from the KernelSU release)
#
# Tunables:
#   ALLOW_SHELL=1   also let adb shell (uid 2000) use su without an allowlist
#                   entry. Handy for setup; 0 forces the allowlist only.
set -u
L=/data/local/tmp/ksu_port.log
p() { echo "$*" >> $L 2>/dev/null; sync; }

rm -f $L
p "boot restore start"

# sig_enforce must be N: the exploit flips it, but the flip is not instantaneous.
i=0
while [ "$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null)" != "N" ] && [ $i -lt 90 ]; do
  sleep 1
  i=$((i+1))
done
p "sig_enforce=N (waited $i s)"

if [ "${ALLOW_SHELL:-0}" = "1" ]; then
  insmod /data/local/tmp/ksu_ctrl.ko allow_shell=1
else
  insmod /data/local/tmp/ksu_ctrl.ko allow_shell=0
fi
p "insmod rc=$?"

mkdir -p /data/local/tmp/kbin
ln -sf /data/adb/ksud /data/local/tmp/kbin/su
chmod 0711 /data/adb 2>/dev/null
chmod 0755 /data/adb/ksud 2>/dev/null
chmod 0777 /data/local/tmp/kbin 2>/dev/null
p "su ready: /data/local/tmp/kbin/su"

# The kernel-side throne scan is deferred by 5s (see docs/LKM-PORT.md); wait for
# it so the Manager gets its driver fd on the next launch.
sleep 6
p "throne: $(dmesg | grep -a 'Crowning manager' | tail -1)"
p "allowlist: $(dmesg | grep -a -e 'load_allow_uid' -e 'invalid selinux_domain' | tail -4)"
p "su(uid2000)=$(/data/local/tmp/kbin/su -c 'id -u' 2>&1)"
p "done"
