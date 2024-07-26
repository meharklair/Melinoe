import yara


def main():
    rules = yara.compile(filepath='Test_rule.yar')

    matches = rules.match('Test.txt')

    print(matches)

if __name__ == '__main__':
    main()