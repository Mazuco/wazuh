#!/usr/bin/python3

import json
import os
import re
import sys
import time
import subprocess
import datetime

if os.name == 'nt':
    import winreg  
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1


_PORTABLE_SEARCH_DIRS_CANDIDATES = [
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    os.environ.get("APPDATA"),
    os.environ.get("LOCALAPPDATA"),
]
PORTABLE_SEARCH_DIRS = [p for p in _PORTABLE_SEARCH_DIRS_CANDIDATES if p]

# Maximum time (seconds) to wait for an uninstall subprocess to complete.
SUBPROCESS_TIMEOUT = 120


# Proper class with PEP-8 name; instantiated before use.
class Message:
    def __init__(self):
        self.alert = ""
        self.command = 0


def write_debug_file(ar_name: str, msg: str) -> None:
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(
            str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S'))
            + " " + ar_name + ": " + msg + "\n"
        )


def write_remediation_alert(
    ar_name: str,
    program_name: str,
    display_name: str,
    returncode: int,
) -> None:
    status = "SUCCESS" if returncode == 0 else "FAILED"

    payload = json.dumps({
        "version": 1,
        "origin": {
            "name": "",
            "module": "wazuh-execd"
        },
        "command": "add",
        "parameters": {
            "extra_args": [],
            "alert": {
                "data": {
                    "program": {
                        "name": program_name
                    }
                }
            },
            "program": ar_name,
            "remediation_status": status,
            "display_name": display_name
        }
    })

    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(
            str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S'))
            + " " + ar_name + ": " + payload + "\n"
        )


def setup_and_check_message(argv: list) -> Message:
    
    msg = Message()

    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        msg.command = OS_INVALID
        return msg

    msg.alert = data

    command = data.get("command")

    if command == "add":
        msg.command = ADD_COMMAND
    elif command == "delete":
        msg.command = DELETE_COMMAND
    else:
        msg.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + str(command))

    return msg


def send_keys_and_check_message(argv: list, keys: list) -> int:
    keys_msg = json.dumps({
        "version": 1,
        "origin": {"name": argv[0], "module": "active-response"},
        "command": "check_keys",
        "parameters": {"keys": keys}
    })

    write_debug_file(argv[0], keys_msg)

    print(keys_msg)
    sys.stdout.flush()

    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return OS_INVALID

    action = data.get("command")

    if action == "continue":
        return CONTINUE_COMMAND
    elif action == "abort":
        return ABORT_COMMAND
    else:
        write_debug_file(argv[0], "Invalid value of 'command'")
        return OS_INVALID




def _require_windows(argv: list, func_name: str) -> bool:
    """Return True on Windows; log and return False otherwise."""
    if os.name != 'nt':
        write_debug_file(argv[0], f"{func_name} is only supported on Windows")
        return False
    return True


def search_registry(program_name: str) -> dict | None:
    # Guard against being called on non-Windows platforms.
    if os.name != 'nt':
        return None

    uninstall_roots = [
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ),
        (
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        ),
    ]

    for hive, path in uninstall_roots:
        try:
            root = winreg.OpenKey(hive, path)
            for i in range(winreg.QueryInfoKey(root)[0]):

                try:
                    subkey_name = winreg.EnumKey(root, i)
                    subkey = winreg.OpenKey(root, subkey_name)

                    display_name = None
                    uninstall_string = None

                    try:
                        display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                    except Exception:
                        pass

                    try:
                        uninstall_string = winreg.QueryValueEx(subkey, "UninstallString")[0]
                    except Exception:
                        pass

                    if display_name and uninstall_string:
                        if program_name.lower() in display_name.lower():
                            return {
                                "display_name": display_name,
                                "uninstall_string": uninstall_string,
                            }

                except Exception:
                    continue

        except Exception:
            continue

    return None


def detect_installer_type(uninstall_string: str) -> str:
    s = uninstall_string.lower()

    if "msiexec" in s:
        return "msi"

    # Distinguish Inno from generic uninst*.exe before falling back to NSIS
    
    if re.search(r'unins\d{3}\.exe', s):
        return "inno"

    if re.search(r'uninst(all(er)?)?\.exe', s):
        if "inno" in s or re.search(r'is\.exe', s):
            return "inno"
        return "nsis"

    return "unknown"


def _sanitize_uninstall_string(uninstall_string: str) -> str:
    """
    Raise ValueError if the uninstall_string contains shell metacharacters
    that could enable injection when the string must be passed through the
    shell (MSI / unknown installers that lack a quoted-list form).
    """
    # Reject obvious injection attempts: pipes, redirects, command chaining.
    if re.search(r'[|&;<>`$]', uninstall_string):
        raise ValueError(
            f"Potentially unsafe characters in uninstall string: {uninstall_string!r}"
        )
    return uninstall_string


def _parse_command_to_list(cmd: str) -> list[str]:
    """
    Convert a command string that may begin with a quoted executable path
    into a list suitable for subprocess with shell=False.
    e.g. '"C:\\foo bar\\unins000.exe" /VERYSILENT'
         -> ['C:\\foo bar\\unins000.exe', '/VERYSILENT']
    """
    match = re.match(r'"([^"]+)"\s*(.*)', cmd)
    if match:
        exe = match.group(1)
        rest = match.group(2).split()
        return [exe] + rest
    return cmd.split()


def build_silent_command(
    uninstall_string: str,
    installer_type: str,
) -> list[str] | None:
    """
    Return the uninstall command as a *list* (never a raw shell string) so
    callers can use shell=False.  Returns None for 'unknown' types where we
    cannot safely construct a silent command.
    """
    s = uninstall_string.lower()

    if installer_type == "msi":

        arguments = re.sub(r'(?i)"?msiexec\.exe"?\s*', '', uninstall_string).strip()

        arguments = re.sub(r'/I\b', '/X', arguments, flags=re.IGNORECASE)
        args_list = arguments.split()
        if not any(a.lower() == "/qn" for a in args_list):
            args_list.append("/qn")
        if not any(a.lower() == "/norestart" for a in args_list):
            args_list.append("/norestart")
        return ["msiexec.exe"] + args_list

    elif installer_type == "nsis":
        cmd_list = _parse_command_to_list(uninstall_string)
        if "/s" not in s:
            cmd_list.append("/S")
        return cmd_list

    elif installer_type == "inno":
        cmd_list = _parse_command_to_list(uninstall_string)
        if "/verysilent" not in s:
            cmd_list.append("/VERYSILENT")
        if "/suppressmsgboxes" not in s:
            cmd_list.append("/SUPPRESSMSGBOXES")
        if "/norestart" not in s:
            cmd_list.append("/NORESTART")
        return cmd_list

    else:
        # Unknown installer type — do not guess; return None so
        # the caller can skip execution and log a warning.
        return None


# Known helper / side-car executable name patterns to skip when searching
# for a portable app's main executable.
_HELPER_EXE_PATTERNS = re.compile(
    r'(updat|crash|helper|report|uninst|setup|install|redist|vcredist)',
    re.IGNORECASE,
)


def find_portable_app(program_name: str) -> tuple[str | None, str | None]:
    search_name = program_name.lower().replace(" ", "")

    for base_dir in PORTABLE_SEARCH_DIRS:
        if not os.path.isdir(base_dir):
            continue

        # Catch Exception, not bare except.
        try:
            for folder in os.listdir(base_dir):
                if search_name not in folder.lower().replace(" ", ""):
                    continue

                folder_path = os.path.join(base_dir, folder)
                if not os.path.isdir(folder_path):
                    continue

                # Prefer the exe whose basename most closely matches the folder name and skip known helpers.
                best_exe: str | None = None
                best_score = -1

                for filename in os.listdir(folder_path):
                    if not filename.lower().endswith(".exe"):
                        continue
                    if _HELPER_EXE_PATTERNS.search(filename):
                        continue

                    # Score by character overlap with the folder name.
                    fname_norm = filename.lower().replace(" ", "").replace(".exe", "")
                    score = sum(c in folder.lower() for c in fname_norm)
                    if score > best_score:
                        best_score = score
                        best_exe = filename

                if best_exe:
                    return os.path.join(folder_path, best_exe), folder_path

        except Exception as e:
            continue

    return None, None


def remove_portable_app(argv: list, program_name: str) -> int:
    if not _require_windows(argv, "remove_portable_app"):
        return OS_INVALID

    exe_path, install_dir = find_portable_app(program_name)

    if not exe_path:
        write_debug_file(
            argv[0],
            f"No portable installation found for: {program_name}"
        )
        return -1

    exe_name = os.path.basename(exe_path)

    try:

        kill_result = subprocess.run(
            ["taskkill", "/F", "/IM", exe_name],
            shell=False,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
        write_debug_file(
            argv[0],
            f"taskkill {exe_name}: exit {kill_result.returncode}"
        )
    except subprocess.TimeoutExpired:
        write_debug_file(argv[0], f"taskkill timed out for: {exe_name}")
    except Exception as e:
        write_debug_file(argv[0], f"taskkill failed: {type(e).__name__}: {e}")

    try:

        rm_result = subprocess.run(
            ["cmd", "/C", "rmdir", "/S", "/Q", install_dir],
            shell=False,
            check=False,
            timeout=SUBPROCESS_TIMEOUT,
        )
        if rm_result.returncode == 0:
            write_debug_file(argv[0], f"Removed directory: {install_dir}")
            return 0
        else:
            write_debug_file(
                argv[0],
                f"rmdir exited {rm_result.returncode}: {install_dir}"
            )
            return rm_result.returncode

    except subprocess.TimeoutExpired:
        write_debug_file(argv[0], f"rmdir timed out for: {install_dir}")
        return -1
    except Exception as e:
        write_debug_file(argv[0], f"Directory removal failed: {type(e).__name__}: {e}")
        return -1


def remove_store_app(argv: list, program_name: str) -> int:
    if not _require_windows(argv, "remove_store_app"):
        return OS_INVALID

    # Sanitize program_name before embedding in PowerShell.
    # Only allow alphanumeric chars, spaces, dots, and hyphens.
    if not re.match(r'^[\w\s.\-]+$', program_name):
        write_debug_file(
            argv[0],
            f"Unsafe characters in program_name, aborting Store removal: {program_name!r}"
        )
        return OS_INVALID

    # Pass the search term via -EncodedCommand
    import base64

    find_script = (
        f"$name = '{program_name}';"
        "$pkg = Get-AppxPackage -AllUsers | "
        "Where-Object { $_.Name -like \"*$name*\" -or $_.PackageFullName -like \"*$name*\" } | "
        "Select-Object -First 1 -ExpandProperty PackageFullName;"
        "Write-Output $pkg"
    )
    encoded_find = base64.b64encode(find_script.encode("utf-16-le")).decode("ascii")

    try:
        
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-EncodedCommand", encoded_find],
            shell=False,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
        package_name = result.stdout.strip()

        if not package_name:
            write_debug_file(
                argv[0],
                f"No Store app package found for: {program_name}"
            )
            return -1

        write_debug_file(argv[0], f"Found Store app package: {package_name}")

        # Validate the returned package name before using it.
        if not re.match(r'^[\w.\-_~]+$', package_name):
            write_debug_file(
                argv[0],
                f"Unexpected characters in package name, aborting: {package_name!r}"
            )
            return OS_INVALID

        remove_script = f"Remove-AppxPackage -AllUsers -Package '{package_name}'"
        encoded_remove = base64.b64encode(remove_script.encode("utf-16-le")).decode("ascii")


        rm_result = subprocess.run(
            ["powershell", "-NonInteractive", "-EncodedCommand", encoded_remove],
            shell=False,
            check=False,
            timeout=SUBPROCESS_TIMEOUT,
        )

        if rm_result.returncode == 0:
            write_debug_file(argv[0], f"Store app removed successfully: {program_name}")
            return 0
        else:
            write_debug_file(
                argv[0],
                f"Store app removal exited with code {rm_result.returncode}: {program_name}"
            )
            return rm_result.returncode

    except subprocess.TimeoutExpired:
        write_debug_file(argv[0], f"PowerShell command timed out for: {program_name}")
        return -1
    except Exception as e:
        write_debug_file(argv[0], f"Store app removal failed: {type(e).__name__}: {e}")
        return -1


def execute_uninstall(argv: list, app: dict) -> int:
    uninstall_string = app["uninstall_string"].strip()
    display_name = app["display_name"]

    write_debug_file(
        argv[0],
        f"Executing uninstall for {display_name}: {uninstall_string}"
    )

    try:
        # Validate the string for shell metacharacters before use.
        try:
            _sanitize_uninstall_string(uninstall_string)
        except ValueError as e:
            write_debug_file(argv[0], f"Uninstall string rejected: {e}")
            return OS_INVALID

        installer_type = detect_installer_type(uninstall_string)
        write_debug_file(argv[0], f"Detected installer type: {installer_type}")

        # Build_silent_command returns None for unknown types; abort rather than guessing.
        cmd_list = build_silent_command(uninstall_string, installer_type)
        if cmd_list is None:
            write_debug_file(
                argv[0],
                f"Cannot determine silent uninstall command for unknown "
                f"installer type; skipping: {display_name}"
            )
            return OS_INVALID

        write_debug_file(argv[0], f"Final uninstall command: {cmd_list}")


        result = subprocess.run(
            cmd_list,
            shell=False,
            check=False,
            timeout=SUBPROCESS_TIMEOUT,
        )

        if result.returncode == 0:
            write_debug_file(argv[0], f"Uninstall completed successfully: {display_name}")
        else:
            write_debug_file(
                argv[0],
                f"Uninstall process exited with code {result.returncode}: {display_name}"
            )

        return result.returncode

    except subprocess.TimeoutExpired:
        write_debug_file(argv[0], f"Uninstall timed out: {display_name}")
        return -1
    except Exception as e:
        write_debug_file(argv[0], f"Uninstall failed: {type(e).__name__}: {e}")
        return -1


def main(argv: list) -> None:
    write_debug_file(argv[0], "Started")

    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ADD_COMMAND:
        alert = msg.alert["parameters"]["alert"]
        keys = [alert["rule"]["id"]]
        action = send_keys_and_check_message(argv, keys)

        if action != CONTINUE_COMMAND:
            if action == ABORT_COMMAND:
                write_debug_file(argv[0], "Aborted")
                sys.exit(OS_SUCCESS)
            else:
                write_debug_file(argv[0], "Invalid command")
                sys.exit(OS_INVALID)

        try:
            program_name = alert["data"]["program"]["name"]
        except (KeyError, TypeError):
            write_debug_file(argv[0], "Failed to extract program name")
            sys.exit(OS_INVALID)

        write_debug_file(argv[0], f"Shadow IT detected: {program_name}")

        app = search_registry(program_name)

        if not app:
            write_debug_file(
                argv[0],
                f"No registry entry found for: {program_name}, "
                f"attempting portable app removal"
            )
            returncode = remove_portable_app(argv, program_name)

            if returncode != 0:
                write_debug_file(
                    argv[0],
                    f"Portable removal failed for: {program_name}, "
                    f"attempting Store app removal"
                )
                returncode = remove_store_app(argv, program_name)

            write_remediation_alert(argv[0], program_name, program_name, returncode)
        else:
            returncode = execute_uninstall(argv, app)
            write_remediation_alert(argv[0], program_name, app["display_name"], returncode)

    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)
