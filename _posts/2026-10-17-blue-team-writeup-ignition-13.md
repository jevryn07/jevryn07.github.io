---
tags: Projects
---

# Blue Team Writeup: ignition-13

## Overview

This was part of **Horse Plinko**, a blue team exercise hosted by the University of Central Florida. I defended ignition-13, a Fedora box with two scored services: SSH and Open WebUI. The red team had left at least five pieces of persistence or sabotage on it, and the scored SSH check was failing because of one of them.

I found and removed two planted shell startup scripts and two disguised cron jobs, traced the SSH check failure to the scoring account's shell being set to `nologin`, and reviewed the firewall and listening ports. Some things are still unconfirmed, listed under Open items.

## Environment

The scoring dashboard shows each check as a row of green and red bars, with the stdout and stderr of the last attempt.

| Item | Detail |
|---|---|
| Host | ignition-13.novalocal (OpenStack VM) |
| OS | Fedora, bash 5.2, firewalld, SELinux |
| Internal IP | 172.16.13.20 |
| My account | plinktern, connecting from 172.16.13.250 |
| Scored services | SSH (logs in as jmoney with a password, runs `echo ok`) and Open WebUI |
| Apps on the box | Open WebUI (uvicorn on 127.0.0.1:8888), Ollama (port 11434) |

## Timeline

All on Oct 17. Times are UTC where the logs gave one (Eastern is UTC minus 4). Steps are in the order I did them.

| # | Time (UTC) | What happened |
|---|---|---|
| 1 | — | Noticed the shell prompt was `-bash-5.2$`. My home directory had no bash config files. Copied them from `/etc/skel` and the normal prompt came back. |
| 2 | — | Scoring dashboard showed SSH down: it authenticated, then got "This account is currently not available." |
| 3 | — | Every failed command in my shell printed a "the horse says: no" box. |
| 4 | 20:29–20:35 | sshd logs showed a steady stream of `Accepted password for jmoney` from many different IPs, about every 10 to 30 seconds. |
| 5 | 20:33:39 | My own login as plinktern from 172.16.13.250. |
| 6 | 20:34:17 | A jmoney login from 6.214.117.28 matched the failed SSH check on the dashboard (4:34:17 PM Eastern) to the second. |
| 7 | — | Checked `/etc/bashrc`. It was stock. Checked `/etc/profile.d/` for files no package owns and found `99-horse.sh` and `hugepages-compactd.sh`. |
| 8 | — | SSH check started flapping between green and red. Still the nologin message. |
| 9 | — | Restarted sshd and firewalld. |
| 10 | — | `/etc/crontab` and `/var/spool/cron` were clean. Found two cron files no package owns in `/etc/cron.d/`: `audit-backlogd` and `systemd-tmpfiles`. |
| 11 | — | While deleting, `MHAHAHAHA...` showed up in my command history. |
| 12 | — | Copied all four planted files to `~/evidence/`, cleared immutable flags, and deleted them. |
| 13 | — | Reviewed firewalld and listening ports. |
| 14 | — | The `a` key started typing `i` in my SSH session. |

## Findings

The red team mostly hid things by naming them after real Linux components. The fastest way to catch them was asking the package manager which files no package installed.

Anything in `/etc/profile.d/` runs every time someone opens a shell, including the scoring check's SSH session. So `hugepages-compactd.sh` ran on every check, and as root whenever I opened a root shell.

| Finding | Location | How I found it | Action |
|---|---|---|---|
| Horse error trap | `/etc/profile.d/99-horse.sh` | Ran `rpm -qf` on every file in `/etc/profile.d/` | Saved to evidence, deleted |
| Disguised startup script | `/etc/profile.d/hugepages-compactd.sh` | Same check. Named to look like a kernel memory feature | Saved to evidence, deleted |
| Disguised cron job | `/etc/cron.d/audit-backlogd` | `rpm -qf` on files in `/etc/cron.d/`. No real "audit-backlogd" exists | Saved to evidence, deleted |
| Disguised cron job | `/etc/cron.d/systemd-tmpfiles` | Same check. The real systemd-tmpfiles runs from a systemd timer, not cron | Saved to evidence, deleted |
| Scoring account broken | jmoney's login shell set to `/sbin/nologin` | Dashboard stdout said "This account is currently not available" | Set back to `/bin/bash` |
| Key remap | `a` types `i` in bash | Noticed while typing | Source not found yet |

## Scored SSH check

The SSH check failed because jmoney's shell was set to `/sbin/nologin`. The checker could log in, but nologin kills every command, so `echo ok` exited with status 1.

At first I thought the flood of `Accepted password for jmoney` logins from random IPs was an attack. Then I matched one at 20:34:17 UTC to the dashboard's failed check at 4:34:17 PM Eastern. That told me the checker logs in as jmoney, with a password, from rotating source IPs.

This changed my plan in two ways:

- I could not turn off password logins or limit SSH to my own account. My original hardening script did both and would have broken scoring.
- I could not block IPs in those ranges, because the checker uses them too.

The fix was `sudo usermod -s /bin/bash jmoney`. The check kept flapping after that, so something on the box was probably setting the shell back. The planted profile.d script and the two cron jobs are the likely causes.

## Firewall and exposed services

The firewall had nothing planted in it. The public zone on eth0 allowed `dhcpv6-client`, `http`, `mdns`, and `ssh`, plus port `80/tcp`, with no rich rules and no port forwards. Cleanup is to drop `mdns`, the duplicate `80/tcp`, and probably `dhcpv6-client`, leaving `http` and `ssh`.

| Port | Bound to | Likely service | Notes |
|---|---|---|---|
| 22 | all interfaces | sshd | Scored, keep open |
| 8888 | 127.0.0.1 | Open WebUI (uvicorn) | Localhost only, good |
| 11434 | all interfaces | Ollama | No auth. Should be bound to 127.0.0.1 |
| 9100 | all interfaces | Unknown, often node_exporter | Not confirmed |
| 5355 | all interfaces | LLMNR (systemd-resolved) | Not needed, can turn off |
| 53 | 127.0.0.53, 127.0.0.54 | systemd-resolved DNS | Normal |
| 323 | 127.0.0.1 | chronyd | Normal |

One thing does not add up. The firewall allows port 80, but nothing listens on 80, and Open WebUI is only on localhost. Something must be passing outside traffic to it, and I have not found what yet.

## Open items

- [ ] Confirm all four planted files are gone with `ls -lab /etc/profile.d/ /etc/cron.d/`, and that they don't come back after 10 minutes
- [ ] Read `hugepages-compactd.sh` and both cron files in `~/evidence/` and write down what they did
- [ ] Find and delete whatever scripts the two cron jobs ran
- [ ] Confirm jmoney's shell stays `/bin/bash` and the SSH check stays green
- [ ] Find where the `a` to `i` key remap is set (`/etc/inputrc`, `~/.inputrc`, or a `bind` line) and remove it
- [ ] Figure out who typed `MHAHAHAHA`. Check `w` for other sessions
- [ ] Find what passes port 80 traffic to Open WebUI on 127.0.0.1:8888
- [ ] Identify what is on port 9100
- [ ] Bind Ollama to 127.0.0.1
- [ ] Change jmoney's password, if the rules allow it

## Lessons learned

- **Find out how scoring works before hardening.** My first plan would have turned off password logins and broken the SSH check. Matching a log timestamp to the dashboard told me which account and auth method the checker uses.
- **Ask the package manager what's not stock.** `rpm -qf` and `rpm -V` found every planted file in seconds. Reading config files by hand found nothing.
- **Fake names look real on purpose.** `hugepages-compactd`, `audit-backlogd`, and `systemd-tmpfiles` in cron all borrowed real component names.
- **Check the whole startup path.** Scripts in `/etc/profile.d/` run for every shell, including the scoring check's SSH session, so a planted script there can break scoring.
- **Save evidence before deleting.** Copying files to `~/evidence/` first means I can still go back and see what they did.
- **Check for other people on the box early.** `w` should be one of the first commands, not something I think of after weird text shows up.
