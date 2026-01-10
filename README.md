# HCL-DominoHunter-NG
Modern tooling for not-so-modern Lotus Notes/HCL Domino webapps.

Based on the 2003 Perl script https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/Domino-Hunter

v2.0 update:
Shamelessly rips features from https://github.com/coldfusion39/domi-owned - all credit to @coldfusion39 for the features I simply copied into my existing tool.

# Overview
Domino-Hunter-NG is the pentester/bounty hunter companion for quickly discovering vulnerabilities and misconfigurations on Lotus Notes/HCL Domino web applications. These applications, while not exactly in mainstream favor with most developers in 2026, are still in very widespread use. A quick Shodan or Google search will corroborate this. Previous tooling for pentesting HCL domino lacks numerous features and modern endpoints/logic that would be desirable to testers. This is primarily a consequence of it being nearly 25 years old. It also ports the script from Perl to Python3 instead and implements the wordlists from SecLists for HCL domino. I also added commands & actions for .nsf files I've found are supported according to the very (poor) documentation on HCL's website. Additional endpoints possible. More can be added as time goes on. Please submit PRs for additional functionality or feature requests.

The tool focuses on discovering exposed `.nsf` databases, enumerating available views and documents, extracting UNIDs, testing supported Domino URL commands, and optionally attempting document access using discovered identifiers. Also adds some other utilities that probably aren't useful in 2026 but who knows, they may be for you.

## Installation

```bash
git clone https://github.com/logansdiomedi/HCL-DominoHunter-NG.git
cd HCL-DominoHunter-NG
pip install -r requirements.txt
python3 domino-hunter-ng.py -h
```

## Usage
Args:
```
Γ¥» python3 domino-hunter-ng.py -h
usage: domino-hunter-ng.py [-h] --host HOST [-u CREDS] [--https] [--port PORT] [--proxy PROXY] [--verbose]
                           [--fingerprint] [--scan] [--brute-force USERLIST] [--dump-hashes] [--quick-console]
                           [-f WORDLIST] [--threads THREADS] [--use-unids USE_UNIDS] [--open-unids]
                           [--password PASSWORD] [-l LOGFILE] [--json-out JSON_OUT] [--hash-prefix HASH_PREFIX]

Domino-Hunter-NG v2.0 - Comprehensive HCL/Lotus Domino Security Testing Tool

options:
  -h, --help            show this help message and exit
  --host HOST           Target host or IP
  -u CREDS              Username:Password for authentication
  --https               Use HTTPS instead of HTTP
  --port PORT           Custom port number
  --proxy PROXY         HTTP proxy (e.g. http://127.0.0.1:8080)
  --verbose             Show 4xx, duplicates, and all output

actions:
  What to do (can combine multiple)

  --fingerprint         Fingerprint the Domino server version and check access to key NSF files
  --scan                Scan for NSF files, test commands, extract UNIDs
  --brute-force USERLIST
                        Brute force credentials using userlist file
  --dump-hashes         Dump account password hashes from names.nsf (requires auth)
  --quick-console       Access interactive Quick Console shell via webadmin.nsf (requires admin)

scan options:
  Options for --scan mode

  -f WORDLIST           Path to NSF file wordlist (default: domino-list.txt)
  --threads THREADS     Number of concurrent threads (default: 10)
  --use-unids USE_UNIDS
                        UNID file to load (defaults to logfile.unids if -l is set)
  --open-unids          Actively try to open UNIDs/noteids with ?OpenDocument & /0/<NOTEID>?OpenDocument

brute force options:
  Options for --brute-force mode

  --password PASSWORD   Password to use for brute force (if not set, uses username as password)

output options:
  Where to save results

  -l LOGFILE            Logfile to write output
  --json-out JSON_OUT   Write structured JSON of DBs, working commands, and UNIDs to this file
  --hash-prefix HASH_PREFIX
                        Prefix for hash dump output files (default: domino)

Examples:
  # Fingerprint server
  domino-hunter-ng.py --host domino.example.com --fingerprint

  # Scan for NSF files with authentication
  domino-hunter-ng.py --host domino.example.com -u admin:password --scan

  # Brute force credentials
  domino-hunter-ng.py --host domino.example.com --brute-force users.txt --password Password123

  # Dump password hashes (requires valid credentials)
  domino-hunter-ng.py --host domino.example.com -u admin:password --dump-hashes

  # Access Quick Console (requires admin credentials)
  domino-hunter-ng.py --host domino.example.com -u admin:password --quick-console

  # Full scan with all features
  domino-hunter-ng.py --host domino.example.com -u admin:password --fingerprint --scan --dump-hashes -l output.txtnt

  # Write output to JSON.
  --json-out JSON_OUT   Write structured JSON of DBs, working commands, and UNIDs to this file
```

## Notes
My recommended methodology is to use this as a starting point. Passively browse the application and look for custom .nsf instances within the application itself. Then, you can supply a command such as:

```
gobuster dir -u https://lab.test/discovered/appPath/ -w /opt/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -x nsf -t 10 --random-agent
```
This will then supply you with additional .nsf endpoints. You can feed those back into the included wordlist.txt if you want Domino-Hunter-NG to analyze them and extract UNIDs and automagically find all commands that work for your new endpoints.


### Caveats
I haven't tested this very well. If DominoHunter-NG deletes your production database and causes your wife to leave you, it's absolutely not my fault. PR if something is broken, please.
