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

    def __init__ (self, rules_path, target_path, rules, write):
        self.rules = rules
        self.rules_path = rules_path
        self.target_path = target_path
        self.write = write

    def compile_rules(self, path):
        try:
            log.info(f'Trying to compile YARA rules for \"{path}\"... ٩(•̤̀ᵕ•̤́๑)ᵒᵏ')
            start = time.perf_counter()
            self.rules_path = path
            self.rules = yara.compile(path)
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
        """Scans the target by either doing a single target scan or a direcotry scan."""
        counter = 0
        log.info('Beginning scan...')
        start = time.perf_counter()
        if (os.path.isfile(self.target_path)):
           counter = self.scan_single(self.target_path, counter)
        elif (os.path.isdir(self.target_path)):
            counter = self.scan_directory(counter)
        else:
            log.warn('Target file or folder does not exist, exiting...')
            exit()
        end = time.perf_counter()
        if counter == 0:
            log.info('No Malware Found (＾▽＾)!!!!')
            if self.write:
                f = open("scan_results\\results.txt", "a",  encoding="utf-8")
                f.write('No Malware Found (＾▽＾)!!!!\n')
                f.close()
        log.misc('I am time itself. What are you?')
        log.info(f'Scan completed in {round(end - start, 9)} seconds!')



    def scan_single(self, target, counter):
        matches = self.rules.match(target)
        counter += len(matches)
        for item in matches:
            if target != self.rules_path:
                if self.write:
                    f = open("scan_results\\results.txt", "a",  encoding="utf-8")
                    f.write(f'MALWARE DETECTED! "{target}" -> {item} {fmt.pick_sad_face()}\n')
                    f.close()
                log.okay(f'MALWARE DETECTED! "{target}" -> {item} {fmt.pick_sad_face()}')

        return counter


    def scan_directory(self, counter):
        # Stack Overflow; User: Ajay; This code is for recursing through a directory
        for root, dirs, files in os.walk(self.target_path):
            path = root.split(os.sep)
            for file in files:
                full_path = os.path.join(root,file)
                counter = self.scan_single(full_path, counter)
        return counter

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
