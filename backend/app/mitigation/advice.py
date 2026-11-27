"""Plain-language recommended steps for each detection rule. Shown for every alert, in every mode: they are advice,
not actions. Keep them short and specific, and honest: an alert is a lead to check, not a verdict."""
from __future__ import annotations

ADVICE: dict[str, list[str]] = {
    "HZ-001": [
        "Check whether the failed sign-ins were really you or someone you know (a forgotten password, an old saved password on a device).",
        "If not, block the source IP so it cannot keep guessing passwords.",
        "Make sure the targeted account has a long, unique password and, where offered, two-step verification.",
        "Look at the account's successful sign-ins around the same time: a success after many failures is the worrying case.",
    ],
    "HZ-002": [
        "Ask the account's owner whether they signed in at that hour.",
        "If they did not, change the account's password and review what it did afterwards.",
    ],
    "HZ-003": [
        "These sign-in attempts used account names that do not exist here, which is typical of automated guessing.",
        "Block the source IP if it is not one of your own devices.",
        "Disable sign-in methods you do not need (for example remote access) so there is less to guess at.",
    ],
    "HZ-004": [
        "Confirm that you or an administrator ran these privileged commands.",
        "If not, treat the account as compromised: change its password, review recent activity and remove unneeded admin rights.",
    ],
    "HZ-005": [
        "Check the service's own log for the reason it keeps failing (a bad update, a full disk, a missing dependency).",
        "Repeated service failures can be an attack on availability or a sign of tampering: confirm the service files are the ones you installed.",
    ],
    "HZ-006": [
        "Lockouts usually follow many wrong passwords. Check whether the owner was simply mistyping or using an old saved password.",
        "If the attempts came from an address you do not know, block that IP.",
        "Unlock the account only after you are sure the attempts were not an attacker's.",
    ],
    "HZ-007": [
        "This alert comes from a statistical model, so it is a hint, not proof. Compare the address's activity with its normal pattern.",
        "Check the address against the threat feeds in Analytics before acting. No automatic action is offered for this rule.",
    ],
    "HZ-009": [
        "Clearing the log is rarely routine. Ask whoever had administrator access at that time whether they did it.",
        "If not, treat the computer as compromised: other evidence may have been erased, so check accounts, services and scheduled tasks.",
        "Keep a copy of other logs you still have, and consider forwarding logs to another machine in future.",
    ],
    "HZ-010": [
        "Check that you or an installer you trust added this service (the name and the file it runs are in the event).",
        "If you do not recognise it, stop and disable the service and scan the file it points to with Scan files.",
    ],
    "HZ-011": [
        "Check that a program you installed created this task; look at what it runs and when.",
        "If you do not recognise it, disable the task and scan the program it runs with Scan files.",
    ],
    "HZ-012": [
        "Confirm that you or someone you expect signed in remotely at this time.",
        "If you do not use Remote Desktop, turn it off. If you do, require strong passwords and do not expose it directly to the internet.",
        "A sign-in from a public address is the riskier case and is rated high.",
    ],
    "HZ-013": [
        "Check which program asked for another account's credentials, and whether you started it.",
        "If it was not you, change that account's password and look for other sign-ins from the same computer.",
    ],
    "HZ-014": [
        "Check that you expected a network sign-in from this address, and that the account is one you know.",
        "Prefer Kerberos over NTLM where you can, and restrict NTLM in the local security policy.",
    ],
    "HZ-015": [
        "Confirm that you or an administrator you trust added this account to the Administrators group.",
        "If not, remove the account from the group and change the passwords of the account that made the change.",
    ],
    "HZ-016": [
        "Read the script in the event. Encoded or downloaded commands that you did not start are a warning sign.",
        "If you do not recognise it, disconnect the computer from the network and scan it with Scan files.",
    ],
    "HZ-017": [
        "Check that you plugged in this device. Unknown drives can carry malware.",
        "Scan the device's files with Scan files before opening them.",
    ],
    "HZ-008": [
        "Do not open or run the file. Quarantining it moves it out of the way without deleting it, and it can be restored.",
        "If you downloaded it from the internet, delete the original download and note where it came from.",
        "Run a full scan with Windows Security, and change passwords if the file was ever run.",
        "A detection can be a false positive. If you are sure the file is safe, restore it from quarantine.",
    ],
}

GENERIC = ["Review the related events, then start an investigation and record what you find."]


def advice_for(rule_id: str) -> list[str]:
    return list(ADVICE.get(rule_id, GENERIC))
