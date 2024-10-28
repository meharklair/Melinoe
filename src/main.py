import click
import Signature_scan
import Yara_scan
from logging.logging import Logging, Formatting
from colorama import Fore, Style

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
log = Logging()
fmt = Formatting()
current_version = "0.3.0" 

@click.command(context_settings=CONTEXT_SETTINGS)
@click.option("-v", "--version", is_flag=True, help="The current version.", required=False)
@click.option("-f", "--file", help="The YARA rule file with which to scan", required=False)
@click.option("-d", "--directory", help="The directory you wish to scan", default=".", required=False)
@click.option("-s", "--signature_scan", is_flag=True, help="specify to run a comparison against a malware database", required=False)



def main(version, file, directory, signature_scan) -> None:
    if version:
        fmt.print_version(current_version)
        exit()
        
    fmt.print_banner(current_version)
    
    # default yara rules I made just cause!!!
    log.info(f'{Fore.GREEN}Beginning default yara scan!! ╰ (´꒳`) ╯{Style.RESET_ALL}')
    scanner = Yara_scan.Scanner(None, directory, None)
    scanner.compile_rules('.\injection_rules.yar')
    scanner.scan_target()
    
    if file and directory:
        fmt.print_separator()
        log.info(f'{Fore.GREEN}Beginning specified yara scan!! ╰ (´꒳`) ╯{Style.RESET_ALL}')
        scanner.rules_path = file
        scanner.compile_rules(scanner.rules_path)
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