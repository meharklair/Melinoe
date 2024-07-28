import yara

class Scan:

    def __init__ (self, rules, target):
        self.rules = rules
        self.target = target


def print_banner():
    pass


def main():


    while True:
        try:
            rules = yara.compile(filepath= input('What is the path to your yara rules?\n'))
            break
        except yara.SyntaxError:
            print('incorrect file type. Files must be of type .yar')
        except yara.Error:
            print('Please enter valid path.')

        
    #rules = yara.compile(filepath='injection_rules.yar')
    matches = rules.match('d:\coding projects\malware development\win32api learning\output\process_injection_OHMYGAHHH.exe')
    Nt_check = rules.match('D:\coding projects\maldev crow\TAPI Injection\output\main.exe')
    print(f"win32 api check {matches}")
    print(f"NT check {Nt_check}")

if __name__ == '__main__':
    main()