import yara, time, os

class Scanner:

    def __init__ (self, rules_path, target_path, rules):
        self.rules_path = rules_path
        self.target_path = target_path
        self.rules = rules
        

    def compile_rules(self):
        try:
            print('attempting to compile yara rules... ٩(•̤̀ᵕ•̤́๑)ᵒᵏ\n')

            start = time.perf_counter()
            self.rules = yara.compile(self.rules_path)
            end = time.perf_counter()

            print('yara rules have successfully compiled!ヽ(•‿•)ノ\n')

            print('Time stops for no one...')
            print(f'yara rules compilied in {round(end - start, 9)} seconds\n')

        except yara.SyntaxError:

            print('The file provided is not a yara file')
            print('exiting...')
            exit()

        except yara.Error:

            print('No such file exists')
            print('exiting...')
            exit()
        

    def scan_target(self):

        if (os.path.isfile(self.target_path)):
            self.scan_single(self.target_path)

        elif (os.path.isdir(self.target_path)):
            self.scan_directory()

        else:
            print('target file or folder does not exist')
            print('exiting...')
            exit()

        
    def scan_single(self, target):

        # error catching
        
        try:
            matches = self.rules.match(target)

        except:
            print('invalid file path')

        for item in matches:
            print(f'MAY CONTAIN MALWARE: "{target}" Contains {item}')

    
    def scan_directory(self):

        # https://stackoverflow.com/questions/16953842/using-os-walk-to-recursively-traverse-directories-in-python
        for root, dirs, files in os.walk(self.target_path):
            path = root.split(os.sep)
            # print((len(path) - 1) * '---', os.path.basename(root))
            for file in files:
               # print(len(path) * '---', file)
                full_path = os.path.join(root,file)
                self.scan_single(full_path)
                

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

    yara_path = input('Enter the path to your yara file: \n')
    file_path = input('Enter the path to the directory or file you would like to scan: \n')
    return (yara_path,file_path)

def main():

    print_banner()

    yara_path,file_path = get_input()

    scanner = Scanner(yara_path, file_path, None)

    scanner.compile_rules()


    scanner.scan_target()
        
    # rules = yara.compile(filepath='injection_rules.yar')
    # matches = rules.match('d:\coding projects\malware development\win32api learning\output')
    #Nt_check = rules.match('D:\coding projects\maldev crow\TAPI Injection\output\main.exe')
    # print(f"win32 api check {matches}")
    #print(f"NT check {Nt_check}")

if __name__ == '__main__':
    main()