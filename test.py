import yara

def main():
    rules = yara.compile(filepath='injection_rules.yar')

    matches = rules.match('d:\coding projects\malware development\win32api learning\output\process_injection_OHMYGAHHH.exe')

    print(matches)

if __name__ == '__main__':
    main()