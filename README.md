# Melinoe
## Summary
Melinoe is a command-line malware scanning tool designed to detect malicious software within specified directories or files. It utilizes YARA rules and a signature database to identify potential threats.
## Future
1. Adding a machine learning algortihm to detect malware based on signatures.
2. Adding Linux support :)  
3. Adding a file monitoring system that can scan new files entering the system.
## Sytem Requirements
- Windows System.
- Python is installed.
## Installation
You should start off by downloading the needed requirements.
```bash
pip install -r requirements.txt
```
or this one because sometimes it can be weird with different python environments.
```bash
python -m pip install -r requirements.txt
```
And last of all make sure you are in the src directory.
## Options
| Option  | Description |
| ------------- | ------------- |
| -v, --version | The current version. |
| -f, --file TEXT | The yara rule file to scan with. |
| -d, --directory TEXT |  The directory or file to scan. |
| -s, --signature_scan | flag option to run a comparison against a signature database. |
| -o, --output | Outputs the results to a file. |
| -df, --default | runs a default yara scan with rules I made (really barebones) |
| -h, --help | displays help message and exits. |
# Demo
short example video:

https://github.com/user-attachments/assets/809af5be-bef8-4b50-98ad-d5e9afcb9bfd

