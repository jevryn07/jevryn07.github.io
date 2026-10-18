---
tags: Projects
---

# Horse Plinko Cyber Challenge Writeup: ignition-13

## Overview

This was a part of the Horse Plinko Cyber Challenge, a blue team competition hosted by the University of Central Florida. I defended ignition-13, a Fedora box with two scored services: SSH and Open WebUI, against a red team that had already planted persistence and sabotage on the box before I started. The red team had left at least seven pieces of persistence or sabotage on it, and the scored SSH check was failing because of one of them.

Over the course of the engagement I had to deal with, from the red team:

- A restricted startup shell I had to escape out of just to get a real bash prompt.
- A wiped-out shell profile in my own home directory that broke my prompt and config.
- A scripted "the horse says: no" error trap that fired on every failed command in my shell.
- Two disguised startup scripts hidden in `/etc/profile.d/`, one named to look like a legitimate kernel memory-management feature, that ran on every shell session — including the scoring check's.
- Two disguised cron jobs in `/etc/cron.d/` posing as real systemd and audit components.
- The scored account's login shell silently flipped to `/sbin/nologin`, which took down the SSH check and kept re-breaking it even after I fixed it, pointing to one of the planted scripts or cron jobs resetting it.
- Someone typing into my own session in real time — `MHAHAHAHA` and repeated `sudo nano systemd-tmpfiles` commands I never ran, while my own `rm` attempts mysteriously failed with "No such file or directory."
- A keyboard remap that silently swapped the `a` and `i` keys mid-session.
- A flood of password logins from rotating source IPs that looked like a brute-force attack at first, but turned out to be the scoring checker itself — a false alarm I had to rule out before touching SSH hardening.
- A hidden backdoor: a custom systemd socket unit listening on port 23 that spawned a bash shell for anyone who connected, no authentication at all.
- A live `wall` broadcast sent to my terminal from root mid-engagement, taunting me directly — proof the red team still had root on the box at that point.
- `PermitRootLogin yes` left enabled in sshd's config, which would have let anyone with root's password log straight in over SSH — likely how the red team kept getting back in as root.

I found and removed two planted shell startup scripts, two disguised cron jobs, and a hidden telnet backdoor disguised as a systemd socket unit. I traced the SSH check failure to the scoring account's shell being set to `nologin`, locked down root login over SSH, and reviewed the firewall and listening ports.

## Environment

The scoring dashboard shows each check as a row of green and red bars, with the stdout and stderr of the last attempt.

| Item | Detail |
|---|---|
| Host | ignition-13.novalocal (OpenStack VM) |
| OS | Fedora, bash 5.2, firewalld, SELinux |
| Internal IP | 172.16.13.20 |
| My account | plinktern, connecting from 172.16.13.250 |
| Scored services | SSH (logs in as jmoney with a password, runs `echo ok`) and Open WebUI, which depends on a web server and database server run from a separate Windows host |
| Services on the box | Ollama (port 11434), node-exporter (port 9100), OpenTelemetry collector (127.0.0.1:8888) |

## SSH check down

This was the first sign something was wrong with scoring. The checker logged in fine (authenticated in about 80 ms), but every command came back with "This account is currently not available." That message comes from `/sbin/nologin`, so I knew the account's shell had been changed.

![SSH check down on the scoring dashboard: authenticated, then "This account is currently not available"](/assets/img/horse-plinko/01-ssh-check-down.png)

## Timeline

All on Oct 17. Times are approximate and in Eastern. Steps are in the order I did them.

| # | Approx. time (Eastern) | What happened |
|---|---|---|
| 1 | — | Escaped a restricted startup shell to get into a real bash shell, which showed bash's bare default prompt, `-bash-5.2$`, because my home directory had no bash config files. Copied them from `/etc/skel` and the normal prompt came back. |
| 2 | — | Scoring dashboard showed SSH down: it authenticated, then got "This account is currently not available." |
| 3 | — | Every failed command in my shell printed a "the horse says: no" box. |
| 4 | ~4:30–4:35 PM | sshd logs showed a steady stream of `Accepted password for jmoney` from many different IPs, about every 10 to 30 seconds. |
| 5 | ~4:34 PM | My own login as plinktern from 172.16.13.250. |
| 6 | ~4:34 PM | A jmoney login from 6.214.117.28 matched the failed SSH check on the dashboard around this same time. |
| 7 | — | Checked `/etc/bashrc`. It was stock. Checked `/etc/profile.d/` for files no package owns and found `99-horse.sh` and `hugepages-compactd.sh`. |
| 8 | — | SSH check started flapping between green and red. Still the nologin message. |
| 9 | — | Restarted sshd and firewalld. |
| 10 | — | `/etc/crontab` and `/var/spool/cron` were clean. Found two cron files no package owns in `/etc/cron.d/`: `audit-backlogd` and `systemd-tmpfiles`. |
| 11 | — | While trying to delete the cron files, `MHAHAHAHA` and repeated `sudo nano systemd-tmpfiles` text showed up in my command line that I did not type, and my `rm` attempts kept failing with "No such file or directory." Someone else was actively typing into my session. |
| 12 | — | Copied all four planted files to `~/evidence/`, cleared immutable flags, and deleted them. |
| 13 | — | Reviewed firewalld and listening ports. |
| 14 | — | The `a` key started typing `i` in my SSH session. |
| 15 | — | While reviewing listening ports with `ss -tulpn`, found an unexpected listener on port 23 tied to a custom systemd socket, `telnet-bash.socket`, that spawned a bash shell for anyone who connected — basically an unauthenticated backdoor. |
| 16 | ~3:06 PM | A live `wall` broadcast came through from root on the box: "that's alot of red huh." Confirmation someone else had concurrent root access while I was working. |
| 17 | — | Disabled and removed `telnet-bash.socket` and `telnet-bash@.service`, reloaded systemd, and confirmed port 23 was closed. |
| 18 | — | Checked `/etc/ssh/sshd_config` and found `PermitRootLogin` uncommented and set to `yes`. Changed it to `no`, tested the config with `sudo sshd -t`, and restarted sshd. |

![Escaping into a bare bash shell: uvicorn access logs above a plain -bash-5.2$ prompt](/assets/img/horse-plinko/02-escaping-roulette.png)
*Right after my shell escape got me out of the roulette and into a real bash shell — the bare prompt is what tipped me off that the config files were missing.*

## Findings

The red team mostly hid things by naming them after real Linux components. The fastest way to catch them was asking the package manager which files no package installed.

Anything in `/etc/profile.d/` runs every time someone opens a shell, including the scoring check's SSH session. So `hugepages-compactd.sh` ran on every check, and as root whenever I opened a root shell.

| Finding | Location | How I found it | Action |
|---|---|---|---|
| Telnet bind shell | `telnet-bash.socket` and `telnet-bash@.service` in `/etc/systemd/system/` | `sudo ss -tulpn` showed port 23 owned by systemd. `systemctl list-sockets` tied it to `telnet-bash.socket`, set to start a session for every connection (`Accept=yes`) | Disabled the socket, stopped running instances, deleted both unit files, ran `daemon-reload` |
| Horse error trap | `/etc/profile.d/99-horse.sh` | Ran `rpm -qf` on every file in `/etc/profile.d/`. The file was tagged `HPCC-REDTEAM:troll-banner` and set an ERR trap that printed the banner after any failed command | Saved to evidence, deleted |
| Disguised startup script | `/etc/profile.d/hugepages-compactd.sh` | Same check. Named to look like a kernel memory feature | Saved to evidence, deleted |
| Disguised cron job | `/etc/cron.d/audit-backlogd` | `rpm -qf` on files in `/etc/cron.d/`. No real "audit-backlogd" exists | Saved to evidence, deleted |
| Disguised cron job | `/etc/cron.d/systemd-tmpfiles` | Same check. The real systemd-tmpfiles runs from a systemd timer, not cron | Saved to evidence, deleted |
| Scoring account broken | jmoney's login shell set to `/sbin/nologin` | Dashboard stdout said "This account is currently not available" | Set back to `/bin/bash` |
| Key remap | `a` types `i` in bash | Noticed while typing | Source not found yet |
| Root login allowed over SSH | `PermitRootLogin yes` in `/etc/ssh/sshd_config` | Reviewed sshd_config while hardening SSH | Set to `no`, tested with `sudo sshd -t`, restarted sshd |

![Combined ss -tulpn and systemctl list-sockets output exposing telnet-bash.socket, followed by the root wall broadcast and the commands used to remove it](/assets/img/horse-plinko/07-telnet-backdoor.png)
*`sudo ss -tulpn` showed port 23 owned by systemd itself; `systemctl list-sockets` tied it to `telnet-bash.socket`. Partway through, root's "that's alot of red huh" broadcast came through — then I disabled the socket, stopped running instances, deleted both unit files, and reloaded systemd.*

![rpm -qf loop over /etc/profile.d/ flagging 99-horse.sh and hugepages-compactd.sh as not owned by any package](/assets/img/horse-plinko/03-finding-startup-scripts.png)
*After `/etc/bashrc` came back stock, looping `rpm -qf` over `/etc/profile.d/` flagged the two files no package installed — you can see the horse banner firing on my own failed `ls` and `cat` commands right above.*

![nano open on 99-horse.sh showing the HPCC-REDTEAM:troll-banner markers and the bash ERR trap](/assets/img/horse-plinko/04-inside-horse-script.png)
*Opening `99-horse.sh` confirmed it was red team work — wrapped in `HPCC-REDTEAM:troll-banner` markers, setting a bash `ERR` trap that prints the "You have an error!" box on every failed command.*

![rpm -qf loop over /etc/cron.d/ flagging audit-backlogd and systemd-tmpfiles as not owned by any package](/assets/img/horse-plinko/05-finding-cron-jobs.png)
*The same ownership check against `/etc/cron.d/` after the SSH check kept flipping back to red. The `/etc/cron.daily/*` line is a false alarm from an empty folder.*

![Terminal showing MHAHAHAHA and repeated sudo nano systemd-tmpfiles text appearing unprompted, with rm failing on files that were right there](/assets/img/horse-plinko/06-someone-else-typing.png)
*While trying to delete the cron files, this showed up in my command line — text I never typed, and `rm` failing with "No such file or directory" on files that were clearly still there. The red team was actively interacting with my session.*

![sshd_config with PermitRootLogin uncommented and set to yes](/assets/img/horse-plinko/08-permitrootlogin-yes.png)
*`PermitRootLogin yes` sitting uncommented in `/etc/ssh/sshd_config` — likely how the red team kept getting back in as root.*

At 3:06 PM, root sent a `wall` broadcast to every terminal: "that's alot of red huh." The red team still had root on the box at that point.

## Root login over SSH was enabled

In `/etc/ssh/sshd_config`, `PermitRootLogin` was uncommented and set to `yes`. That let anyone with root's password log straight in as root over SSH, which may be one way the red team kept getting back in as root. I changed it to `PermitRootLogin no`, tested the config with `sudo sshd -t`, and restarted sshd.

This was safe for scoring because the SSH checker logs in as jmoney, not root. Admins still get root through their own accounts with `sudo`, which also leaves a log of who did what.

## Scored SSH check

The SSH check failed because jmoney's shell was set to `/sbin/nologin`. The checker could log in, but nologin kills every command, so `echo ok` exited with status 1.

At first I thought the flood of `Accepted password for jmoney` logins from random IPs was an attack. Then I matched one, around 4:34 PM Eastern, to the dashboard's failed check at that same time. That told me the checker logs in as jmoney, with a password, from rotating source IPs.

This changed my plan in two ways:

- I could not turn off password logins or limit SSH to my own account. My original hardening script did both and would have broken scoring.
- I could not block IPs in those ranges, because the checker uses them too.

The fix was `sudo usermod -s /bin/bash jmoney`. The check kept flapping after that, so something on the box was probably setting the shell back. The planted profile.d script and the two cron jobs are the likely causes.

After my first fix, the SSH check started mixing green and red instead of staying red. A random pattern like this meant something on the box kept undoing my fix, which is what sent me looking for scheduled jobs and shell startup scripts.

![Scoring dashboard grid flapping between green and red squares after the first fix](/assets/img/horse-plinko/09-check-flapping.png)

## Firewall and exposed services

The firewall had nothing planted in it. The public zone on eth0 allowed `dhcpv6-client`, `http`, `mdns`, and `ssh`, plus port `80/tcp`, with no rich rules and no port forwards. Cleanup is to drop `mdns`, the duplicate `80/tcp`, and probably `dhcpv6-client`, leaving `http` and `ssh`.

![firewall-cmd --list-all output showing the public zone's allowed services and ports](/assets/img/horse-plinko/10-firewall-review.png)

Nothing on this box listens on port 80, and Open WebUI does not show up in the `ss` output. Open WebUI depends on a web server and database server run from a separate Windows host, so it's likely served from there — I have not confirmed this.

![Initial ss -tulpn run without sudo, showing listeners on 9100, 8888, and 11434 with no process names](/assets/img/horse-plinko/11-listening-ports.png)
*This first `ss -tulpn` run was without `sudo`, so the process names are blank. Rerunning it with `sudo` later is what led to the telnet backdoor.*

| Port | Bound to | Likely service | Notes |
|---|---|---|---|
| 22 | all interfaces | sshd | Scored, keep open |
| 23 | all interfaces | Backdoor: planted `telnet-bash.socket` | Found live, removed |
| 8888 | 127.0.0.1 | otelcol-contrib (OpenTelemetry collector) | Localhost only |
| 11434 | all interfaces | Ollama | No auth. Should be bound to 127.0.0.1 |
| 9100 | all interfaces | node-exporter (systemd socket) | Prometheus metrics, not scored |
| 5355 | all interfaces | LLMNR (systemd-resolved) | Not needed, can turn off |
| 53 | 127.0.0.53, 127.0.0.54 | systemd-resolved DNS | Normal |
| 323 | 127.0.0.1 | chronyd | Normal |

## Lessons learned

- **Find out how scoring works before hardening.** My first plan would have turned off password logins and broken the SSH check. Matching a log timestamp to the dashboard told me which account and auth method the checker uses.
- **Ask the package manager what's not stock.** `rpm -qf` and `rpm -V` found every planted file in seconds. Reading config files by hand found nothing.
- **Fake names look real on purpose.** `hugepages-compactd`, `audit-backlogd`, and `systemd-tmpfiles` in cron all borrowed real component names.
- **Check the whole startup path.** Scripts in `/etc/profile.d/` run for every shell, including the scoring check's SSH session, so a planted script there can break scoring.
- **Save evidence before deleting.** Copying files to `~/evidence/` first means I can still go back and see what they did.
- **Check for other people on the box early.** `w` should be one of the first commands, not something I think of after weird text shows up.
- **A listening port doesn't mean a running daemon.** The telnet backdoor only showed up because systemd socket activation spawns the process on connection — `systemctl list-sockets --all` next to `ss -tulpn` is what caught it.
