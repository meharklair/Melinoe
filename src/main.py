import click
import Signature_scan
import Yara_scan
from logging.logging import Logging, Formatting

log = Logging()
fmt = Formatting()
current_version = "0.2.3" 

@click.command(no_args_is_help = True)
@click.option("-v", "--version", is_flag=True, help="The current version.", required=False)
@click.option("-f", "--file", help="The YARA rule file with which to scan", required=False)
@click.option("-d", "--directory", help="The directory you wish to scan", default=".", required=False)
@click.option("-s", "--signature_scan", is_flag=True, help="specify to run a comparison against a malware database", required=False)


def main(version, file, directory, signature_scan) -> None:
    if version:
        # fix this to not print banner twice
        fmt.print_banner(current_version)

    if file and directory:
        fmt.print_banner(current_version)
        scanner = Yara_scan.Scanner(file, directory, None)
        scanner.compile_rules()
        scanner.scan_target()
    if directory and signature_scan:
        # need to implment a separator
        scanner = Signature_scan.Scanner(directory, None)
        scanner.download_database()
        scanner.scan_target()
     
if __name__ == '__main__':
    main()