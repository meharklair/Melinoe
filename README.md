# Melinoe
## Summary
Melinoe is a malware scanning script that so far uses yara rules and a signature database to scan for malware in a specified directory or file.
## Future
1. Adding a machine learning algortihm to detect malware based on signatures  
2. a file monitoring system that can scan new files entering the system.
## Options
| Option  | Description |
| ------------- | ------------- |
| -v, --version | The current version. |
| -f, --file TEXT | The yara rule file to scan with. |
| -d, --directory TEXT |  The directory or file to scan. |
| -s, --signature_scan | flag option to run a comparison against a signature database. |
| -o, --output | Outputs the results to a file. |
| -h, --help | displays help message and exits. |
## Dependancies
pip install yara-python
pip install click
pip install colorama
