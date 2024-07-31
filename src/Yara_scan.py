import yara, time, os, random
from logging.logging import Logging

log = Logging()

class Scanner:
    def __init__ (self, rules_path, target_path, rules):
        self.rules_path = rules_path
        self.target_path = target_path
        self.rules = rules

    def compile_rules(self):
        try:
            log.info('attempting to compile yara rules... ٩(•̤̀ᵕ•̤́๑)ᵒᵏ\n')
            start = time.perf_counter()
            self.rules = yara.compile(self.rules_path)
            end = time.perf_counter()
            log.okay('yara rules have successfully compiled!ヽ(•‿•)ノ\n')
            log.misc('time cannot be stopped...')
            log.info(f'yara rules compilied in {round(end - start, 9)} seconds\n')

        except yara.SyntaxError:
            log.warn('the file provided is not a yara file, exiting...')
            exit()

        except yara.Error:
            log.warn('no such file exists, exiting...')
            exit()

    def scan_target(self):

        """
        middle man function for scanning and delegates to scan_directory() or scan_single()
        """

        log.info('beginning scan...')
        start = time.perf_counter()
        if (os.path.isfile(self.target_path)):
            self.scan_single(self.target_path)
        elif (os.path.isdir(self.target_path)):
            self.scan_directory()
        else:
            log.warn('target file or folder does not exist, exiting...')
            exit()
        end = time.perf_counter()
        log.okay('scan completed!\n')
        log.misc('i am time itself. what are you?')
        log.info(f'Scan finished in {round(end - start, 9)} seconds\n')
        
    def scan_single(self, target):
        matches = self.rules.match(target)
        for item in matches:
            log.okay(f"MALWARE DETECTED! : '{target}' -> {item} DETECTED {pick_sad_face()}")

    def scan_directory(self):
        # https://stackoverflow.com/questions/16953842/using-os-walk-to-recursively-traverse-directories-in-python
        for root, dirs, files in os.walk(self.target_path):
            path = root.split(os.sep)
            # print((len(path) - 1) * '---', os.path.basename(root))
            for file in files:
               # print(len(path) * '---', file)
                full_path = os.path.join(root,file)
                self.scan_single(full_path)
                
def pick_sad_face():
    faces = ['( ・⌓・｀)', '(つ﹏<。)', '( ཀ ʖ̯ ཀ)']
    return random.choice(faces)

def print_banner():
    banner = r"""
     ______   _______  _______ _________           _________ _______    _______           _______  _______  _        _______  _______ 
    (  __  \ (  ____ \(  ___  )\__   __/|\     /|  \__   __/(  ___  )  (  ____ \|\     /|(  ____ )(  ___  )( (    /|(  ___  )(  ____ \
    | (  \  )| (    \/| (   ) |   ) (   | )   ( |     ) (   | (   ) |  | (    \/| )   ( || (    )|| (   ) ||  \  ( || (   ) || (    \/
    | |   ) || (__    | (___) |   | |   | (___) |     | |   | |   | |  | |      | (___) || (____)|| |   | ||   \ | || |   | || (_____ 
    | |   | ||  __)   |  ___  |   | |   |  ___  |     | |   | |   | |  | |      |  ___  ||     __)| |   | || (\ \) || |   | |(_____  )
    | |   ) || (      | (   ) |   | |   | (   ) |     | |   | |   | |  | |      | (   ) || (\ (   | |   | || | \   || |   | |      ) |
    | (__/  )| (____/\| )   ( |   | |   | )   ( |     | |   | (___) |  | (____/\| )   ( || ) \ \__| (___) || )  \  || (___) |/\____) |
    (______/ (_______/|/     \|   )_(   |/     \|     )_(   (_______)  (_______/|/     \||/   \__/(_______)|/    )_)(_______)\_______)
    """
    print(banner)
    time.sleep(1)

def get_input():
    yara_path = input('[>] enter the path to your yara file: \n')
    file_path = input('[>] enter the path to the directory or file you would like to scan: \n')
    return (yara_path,file_path)

def main():
    print_banner()
    yara_path,file_path = get_input()
    scanner = Scanner(yara_path, file_path, None)
    scanner.compile_rules()
    scanner.scan_target()
    log.misc('return to shadow, now!')

if __name__ == '__main__':
    main()
