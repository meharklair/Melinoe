import os
import yara
import time
import click
from logging.logging import Logging, Formatting

log = Logging()
fmt = Formatting()
current_version = "0.1.1" 

class Scanner:
    """
    Main scanning component of the program
    """

    def __init__ (self, rules_path, target_path, rules):
        self.rules = rules
        self.rules_path = rules_path
        self.target_path = target_path

    def compile_rules(self):
        try:
            log.info(f'Trying to compile YARA rules for \"{self.rules_path}\"... ٩(•̤̀ᵕ•̤́๑)ᵒᵏ')
            start = time.perf_counter()
            self.rules = yara.compile(self.rules_path)
            end = time.perf_counter()
            log.okay(f'YARA rules have successfully compiled in {round(end - start, 9)} seconds! ヽ(•‿•)ノ')
            log.misc('Time cannot be stopped...')
        except yara.SyntaxError:
            log.warn('The file provided is not a YARA file, exiting...')
            exit()
        except yara.Error:
            log.warn('No such file exists, exiting...')
            exit()

    def scan_target(self):
        log.info('Beginning scan...')
        start = time.perf_counter()
        if (os.path.isfile(self.target_path)):
            self.scan_single(self.target_path)
        elif (os.path.isdir(self.target_path)):
            self.scan_directory()
        else:
            log.warn('Target file or folder does not exist, exiting...')
            exit()
        end = time.perf_counter()
        log.info(f'Scan completed in {round(end - start, 9)} seconds!')
        log.misc('I am time itself. What are you?')
        
    def scan_single(self, target):
        matches = self.rules.match(target)
        for item in matches:
            log.okay(f'MALWARE DETECTED! "{target}" -> {item} {fmt.pick_sad_face()}')

    def scan_directory(self):
        # https://stackoverflow.com/questions/16953842/using-os-walk-to-recursively-traverse-directories-in-python
        for root, dirs, files in os.walk(self.target_path):
            path = root.split(os.sep)
            # print((len(path) - 1) * '---', os.path.basename(root))
            for file in files:
               # print(len(path) * '---', file)
                full_path = os.path.join(root,file)
                self.scan_single(full_path)

@click.command(no_args_is_help = True)
@click.option("-v", "--version", is_flag=True, help="The current version.", required=False)
@click.option("-f", "--file", help="The YARA rule file with which to scan", required=False)
@click.option("-d", "--directory", help="The directory you wish to scan", default=".", required=False)

def main(version, file, directory) -> None:

    if version:
        fmt.print_banner(current_version)

    if file and directory:
        fmt.print_banner(current_version)
        scanner = Scanner(file, directory, None)
        scanner.compile_rules()
        scanner.scan_target()
        log.misc('Return to shadow, now!')

if __name__ == '__main__':
    main()
