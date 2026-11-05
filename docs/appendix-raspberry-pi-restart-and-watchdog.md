# Raspberry Pi: Scheduled Restart and Watchdog

Two complementary mechanisms for keeping a Raspberry Pi healthy:

- **Scheduled reboot**: a clean, planned restart at a set time.
- **Watchdog**: an automatic hard reset if the system freezes.

---

## Part 1: Scheduled Restart

### Option 1: Cron (easiest)

Edit root's crontab:

```bash
sudo crontab -e
```

Reboot every day at 04:00:

```
0 4 * * * /sbin/shutdown -r now
```

Fields: `minute hour day-of-month month day-of-week`

More examples:

```
# Every Monday at 03:30
30 3 * * 1 /sbin/shutdown -r now

# First day of every month at 05:00
0 5 1 * * /sbin/shutdown -r now
```

Using `sudo crontab -e` (root's crontab) means `sudo` is not needed inside the command. `/sbin/reboot` also works in place of `shutdown -r now`.

### Option 2: systemd timer

Better if you want logging and cleaner control.

Create the service:

```bash
sudo nano /etc/systemd/system/scheduled-reboot.service
```

```ini
[Unit]
Description=Scheduled reboot

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl reboot
```

Create the timer:

```bash
sudo nano /etc/systemd/system/scheduled-reboot.timer
```

```ini
[Unit]
Description=Reboot every day at 04:00

[Timer]
OnCalendar=*-*-* 04:00:00
Persistent=false

[Install]
WantedBy=timers.target
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now scheduled-reboot.timer
systemctl list-timers
```

### Option 3: One-time reboot

```bash
sudo shutdown -r 04:00
```

Cancel with:

```bash
sudo shutdown -c
```

### Things to check

| Topic | Note |
|---|---|
| **Time zone** | The Pi uses its own system time. Check with `date`; set with `sudo raspi-config` (Localisation Options) or `sudo timedatectl set-timezone Europe/Stockholm`. |
| **No RTC** | A Pi has no battery-backed clock. Without NTP sync the time can be wrong after a power loss. Verify with `timedatectl`. |
| **SD card wear** | Frequent reboots are fine as long as shutdowns are clean (`shutdown -r`, not a power cut). |
| **Reboot loops** | Be careful combining `@reboot` with time-based logic and a possibly wrong clock. |

---

## Part 2: Hardware Watchdog

The Pi's SoC has a hardware watchdog timer. If nothing "pets" it within the timeout, the hardware resets the board, even if the kernel is completely frozen. The maximum timeout is about 15 seconds.

### Check whether it is available

On current Raspberry Pi OS kernels the driver is normally already present, so `dtparam=watchdog=on` is usually **not** needed.

```bash
ls -l /dev/watchdog*
sudo wdctl
dmesg | grep -i wdt
```

If `/dev/watchdog` exists and `wdctl` shows a device (`bcm2835-wdt`), you are ready. Only if it is missing, add this to `/boot/firmware/config.txt` and reboot:

```
dtparam=watchdog=on
```

### Option A: systemd's built-in watchdog (simplest)

Edit `/etc/systemd/system.conf`:

```ini
[Manager]
RuntimeWatchdogSec=15
RebootWatchdogSec=2min
```

- `RuntimeWatchdogSec`: systemd pings the watchdog while running. If systemd or the kernel hangs, the hardware resets the Pi.
- `RebootWatchdogSec`: safety net so a stuck reboot also ends in a hard reset.

Apply and verify:

```bash
sudo systemctl daemon-reexec
systemctl show -p RuntimeWatchdogUSec
sudo wdctl
```

This only detects a hung kernel or systemd, **not** a hung application. For individual services, add `WatchdogSec=` in the unit file. The service must then call `sd_notify("WATCHDOG=1")` periodically, and is usually paired with `Restart=on-watchdog` or `Restart=always`.

### Option B: the `watchdog` daemon (more health checks)

Useful if you want to reboot on conditions other than a total freeze.

```bash
sudo apt install watchdog
sudo nano /etc/watchdog.conf
```

Typical settings:

```
watchdog-device = /dev/watchdog
watchdog-timeout = 15
interval = 1
max-load-1 = 24
min-memory = 1
realtime = yes
priority = 1

# Optional: reboot if the network is unreachable
# ping = 192.168.1.1

# Optional: reboot if too hot
# temperature-sensor = /sys/class/thermal/thermal_zone0/temp
# max-temperature = 80000
```

Enable it:

```bash
sudo systemctl enable --now watchdog
sudo systemctl status watchdog
```

> **Do not run Option A and Option B together.** Both want exclusive access to `/dev/watchdog`. Pick one (leave `RuntimeWatchdogSec` unset if you use the daemon).

### Testing

These force an unclean reset, so only run them when you are ready for that.

Fork bomb (starves the system until the watchdog trips):

```bash
:(){ :|:& };:
```

Kernel crash:

```bash
sudo sh -c 'echo 1 > /proc/sys/kernel/sysrq; echo c > /proc/sysrq-trigger'
```

The Pi should reset within roughly 15 seconds.

### Things to be aware of

- **Unclean reset**: A watchdog reset is like a power cut, so there is a small risk of SD card corruption. It is a last resort, not a replacement for a scheduled clean `shutdown -r`.
- **Boot loops**: If something at boot hangs every time, the Pi will reboot repeatedly. Keep a way to disable the watchdog (e.g. edit `system.conf` from the SD card on another machine).
- **Network checks**: With `ping =` in the daemon, a dead router can cause endless reboots. Use with care.
- **Pi 5**: Also has a hardware watchdog, and the same systemd approach works.

---

## Quick reference

| Goal | Command / setting |
|---|---|
| Daily reboot at 04:00 (cron) | `0 4 * * * /sbin/shutdown -r now` in `sudo crontab -e` |
| One-time reboot | `sudo shutdown -r 04:00` |
| Cancel scheduled reboot | `sudo shutdown -c` |
| Check timers | `systemctl list-timers` |
| Check watchdog device | `sudo wdctl` |
| systemd watchdog | `RuntimeWatchdogSec=15` in `/etc/systemd/system.conf` |
| Watchdog daemon | `sudo apt install watchdog`, edit `/etc/watchdog.conf` |
