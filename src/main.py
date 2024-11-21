import click
import os
import Signature_scan
import Yara_scan
from logging.logging import Logging, Formatting
from colorama import Fore, Style

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
log = Logging()
fmt = Formatting()
current_version = "0.5.0" 
@click.command(context_settings=CONTEXT_SETTINGS, no_args_is_help = True)
@click.option("-v", "--version", is_flag=True, help="The current version.", required=False)
@click.option("-f", "--file", help="The YARA rule file with which to scan", required=False)
@click.option("-df", "--default", is_flag=True, help="Runs a default scan with creator made yara rules (really barebones right now)", default=False, required=False)
@click.option("-d", "--directory", help="The directory you wish to scan", default=".", required=False)
@click.option("-s", "--signature_scan", is_flag=True, help="specify to run a comparison against a malware database", required=False)
@click.option("-o", "--output", is_flag=True, help="Outputs the results in a file", default=False, required=False)


def main(version, file, default, directory, signature_scan, output) -> None:
    if version:
        fmt.print_version(current_version)
        exit()
        
    fmt.print_banner(current_version)
    if output:
        create_output_files(output)
    # default yara rules I made just cause!!!
    if output:
        # gotta be a better way to do this
        f = open("scan_results\\results.txt", "a",  encoding="utf-8")
        f.write(f'Beginning default yara scan!! ╰ (´꒳`) ╯\n')
        f.close()
        
    if default:
        log.info(f'{Fore.GREEN}Beginning default yara scan!! ╰ (´꒳`) ╯{Style.RESET_ALL}')
        scanner = Yara_scan.Scanner(None, directory, None, output)
        scanner.compile_rules('Rules\\injection_rules.yar')
        scanner.scan_target()
    
    if file and directory:
        fmt.print_separator()

        if output:
            f = open("scan_results\\results.txt", "a",  encoding="utf-8")
            fmt.write_separator(f)
            f.write(f'Beginning specified yara scan!! ╰ (´꒳`) ╯\n')
            f.close()
            
        log.info(f'{Fore.GREEN}Beginning specified yara scan!! ╰ (´꒳`) ╯{Style.RESET_ALL}')
        scanner.rules_path = file
        scanner.compile_rules(scanner.rules_path)
        scanner.scan_target()

    if directory and signature_scan:
        fmt.print_separator()
        if output:
            f = open("scan_results\\results.txt", "a",  encoding="utf-8")
            fmt.write_separator(f)
            f.write(f'Beginning signature scan!! (•‿•)\n')
            f.close()    
        log.info(f'{Fore.GREEN}Beginning signature scan!! (•‿•){Style.RESET_ALL}')
        scanner = Signature_scan.Scanner(directory, None, output)
        up_to_date = scanner.check_download()
        if not up_to_date:
            scanner.download_database()
        scanner.scan_target()

    log.misc(f'{Fore.GREEN}All scans completed ⊂(▀¯▀⊂ ){Style.RESET_ALL}')
    log.misc('Return to shadow, now!')

def create_output_files(output):
    file = r'scan_results\\results.txt'
    path = r'scan_results'
    if not os.path.exists(path):
        os.makedirs(path)
    if os.path.exists(file):
        os.remove(file)

if __name__ == '__main__':
    main()