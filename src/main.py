import click
import Signature_scan
import Yara_scan
from logging.logging import Logging, Formatting
from colorama import Fore, Style

log = Logging()
fmt = Formatting()
current_version = "0.2.5" 

@click.command(no_args_is_help = True)
@click.option("-v", "--version", is_flag=True, help="The current version.", required=False)
@click.option("-f", "--file", help="The YARA rule file with which to scan", required=False)
@click.option("-d", "--directory", help="The directory you wish to scan", default=".", required=False)
@click.option("-s", "--signature_scan", is_flag=True, help="specify to run a comparison against a malware database", required=False)


def main(version, file, directory, signature_scan) -> None:
    if version:
        fmt.print_version(current_version)
        exit()
        
    fmt.print_banner(current_version)
    if file and directory:
        log.info(f'{Fore.GREEN}Beginning yara scan!! ╰ (´꒳`) ╯{Style.RESET_ALL}')
        scanner = Yara_scan.Scanner(file, directory, None)
        scanner.compile_rules()
        scanner.scan_target()

    if directory and signature_scan:
        if file != None:
            fmt.print_separator()
        log.info(f'{Fore.GREEN}Beginning signature scan!! (•‿•){Style.RESET_ALL}')
        scanner = Signature_scan.Scanner(directory, None)
        scanner.download_database()
        scanner.scan_target()

    log.misc(f'{Fore.GREEN}All scans completed ⊂(▀¯▀⊂ ){Style.RESET_ALL}')
    log.misc('Return to shadow, now!')


if __name__ == '__main__':
    main()