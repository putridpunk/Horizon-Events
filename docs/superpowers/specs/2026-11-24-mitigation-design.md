# Alert mitigation: design

**Goal.** Every alert shows plain-language recommended steps. For two kinds of alert the app can also carry out the
step on this PC, only with the user's approval (default) and, for one of them, optionally automatically.

**Approved scope (A).** Only two actions: **block a source IP** (Windows Firewall) and **quarantine a malware file**.
Each action has its own mode: *Off*, *Ask first* (default) or *Automatic*.

**Block IP.** Needs administrator rights, so each block is approved in the app and then confirmed in Windows' own
permission prompt; nothing keeps standing privileges. The rule is `Horizon Events block <ip>` (inbound, remote IP).
Success is checked by reading the rule back, not by the exit code. Undo ("Remove block") is the same two-step.
*Automatic* is not offered for this action (it would need a standing privileged helper; out of scope).
Offered only for rules HZ-001, HZ-003, HZ-006 and never for the ML rule HZ-007. Refused for: non-public addresses
(unless the user allows them in settings), this computer's own addresses, loopback/multicast/reserved, and anything
on the user's allowlist. Blocks carry an expiry date (default 7 days); the app flags expired blocks and offers
removal, but cannot remove them silently (that would need the privileged helper).

**Quarantine.** No admin needed: the app moves the flagged file (only the path Defender reported, and only for
HZ-008 alerts) into `<data>/quarantine/<id>.quarantined`, never from the Windows folder, and records where it came from;
**Restore** moves it back (refuses to overwrite). *Automatic* quarantines straight after a scan detection.

**History.** Every proposal and action is stored (`mitigations` table) and listed on a Mitigation page with
Remove block / Restore buttons.

**Non-goals.** Disabling accounts, stopping services, resetting passwords, a privileged background helper, silent
block removal. **Anti-goal:** an automatic action that can lock the user out; hence the allowlist, no private
addresses by default, no ML-only action, and everything reversible.

**Alternatives rejected.** A one-time privileged helper (automatic blocking): standing privilege, bigger attack
surface. Running the whole app elevated: prompt at every launch, everything runs with full rights.
