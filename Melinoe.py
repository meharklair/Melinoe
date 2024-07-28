import yara, time

class Scanner:

    def __init__ (self, rules_path, target_path, rules):
        self.rules_path = rules_path
        self.target_path = target_path
        self.rules = rules
        

    def compile_rules(self):
        try:
            print('attempting to compile yara rules...')

            start = time.time()
            self.rules = yara.compile(self.rules_path)
            end = time.time()

            print(f'yara rules compilied in {round(end - start, 9)} seconds')

        except:
            print('invalid yara file path')
            print('exiting....')
            exit()
    
    def scan_target(self):

        print('starting file or directory scan\n')

        # error catching
        
        try:
            matches = self.rules.match(self.target_path)

        except:
            print('invalid file path')

        for item in matches:
            print(f'MAY CONTAIN MALWARE: "{self.target_path}" Contains {item}')
        



def print_banner():
    pass

def get_input():

    yara_path = input('Enter the path of the yara file: \n')
    file_path = input('Enter the path to the directory or file: \n')
    return (yara_path,file_path)

def main():

    yara_path,file_path = get_input()

    scanner = Scanner(yara_path, file_path, None)

    scanner.compile_rules()
    
    print('yara rules have successfully compiled!')

    scanner.scan_target()
        
    #rules = yara.compile(filepath='injection_rules.yar')
    #matches = rules.match('d:\coding projects\malware development\win32api learning\output\process_injection_OHMYGAHHH.exe')
    #Nt_check = rules.match('D:\coding projects\maldev crow\TAPI Injection\output\main.exe')
    #print(f"win32 api check {matches}")
    #print(f"NT check {Nt_check}")

if __name__ == '__main__':
    main()