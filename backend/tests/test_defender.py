import pytest

from app.scanning import defender
from app.scanning.defender import CLEAN, ERROR, THREAT, Finding, parse_output, scan_path

# Output recorded from MpCmdRun.exe on Windows 11 (the detection is the harmless EICAR test file).
CLEAN_OUT = "Scan starting...\nScan finished.\nScanning " + r"C:\Users\a\b.txt" + " found no threats.\n"
THREAT_OUT = r"""Scan starting...
Scan finished.
Scanning C:\Temp\probe\eicar.txt found 1 threats.

<===========================LIST OF DETECTED THREATS==========================>
----------------------------- Threat information ------------------------------
Threat                  : Virus:DOS/EICAR_Test_File
Resources               : 1 total
    file                : C:\Temp\probe\eicar.txt
-------------------------------------------------------------------------------
"""
MISSING_OUT = ("[Failed][0x80070002] The system cannot find the file specified.\n"
               "CmdTool: Failed with hr = 0x80070002. Check the MpCmdRun.log for more information\n")


def test_clean_scan():
    assert parse_output(CLEAN_OUT, r"C:\Users\a\b.txt").status == CLEAN


def test_detection_is_itemised():
    out = parse_output(THREAT_OUT, r"C:\Temp\probe")
    assert out.status == THREAT
    assert out.findings == [Finding("Virus:DOS/EICAR_Test_File", r"C:\Temp\probe\eicar.txt")]


def test_several_threats_in_a_folder_are_all_listed():
    text = (r"Scanning C:\d found 2 threats." "\n" r"Threat : Trojan:Win32/A" "\nResources : 1 total\n" r"   file : C:\d\a.exe" "\n"
            r"Threat : Virus:Win32/B" "\nResources : 1 total\n" r"   file : C:\d\b.exe" "\n")
    out = parse_output(text, r"C:\d")
    assert [(f.threat, f.path) for f in out.findings] == [("Trojan:Win32/A", r"C:\d\a.exe"), ("Virus:Win32/B", r"C:\d\b.exe")]


def test_a_detection_without_details_still_counts():
    out = parse_output("Scanning x found 1 threats.\n", r"C:\d")
    assert out.status == THREAT and out.findings == [Finding("Unidentified threat", r"C:\d")]


def test_a_failure_is_an_error_never_clean():
    out = parse_output(MISSING_OUT, r"C:\x")
    assert out.status == ERROR and "0x80070002" in out.message


def test_empty_output_is_an_error():
    assert parse_output("", r"C:\x").status == ERROR


def test_scan_path_builds_a_report_only_command():
    seen = {}

    def runner(args, timeout):
        seen["args"], seen["timeout"] = args, timeout
        return 0, CLEAN_OUT

    assert scan_path(r"C:\f.txt", runner=runner, tool="MpCmdRun.exe").status == CLEAN
    assert seen["args"] == ["MpCmdRun.exe", "-Scan", "-ScanType", "3", "-File", r"C:\f.txt", "-DisableRemediation"]


@pytest.mark.parametrize("exc,expect", [(TimeoutError("slow"), "too long"), (OSError("denied"), "could not be started")])
def test_runner_failures_become_errors(exc, expect):
    def runner(args, timeout):
        raise exc

    out = scan_path(r"C:\f", runner=runner, tool="MpCmdRun.exe")
    assert out.status == ERROR and expect in out.message


def test_missing_defender_is_reported(monkeypatch):
    monkeypatch.setattr(defender, "find_defender", lambda: None)
    out = scan_path(r"C:\f")
    assert out.status == ERROR and "not found" in out.message
