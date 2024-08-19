import clamd


class Scanner:

    def __init__(self, clamd_daemon, target):
        self.clamd_daemon = clamd_daemon
        self.target = target

    def single_target(self):
        self.clamd_daemon.__init__(host='127.0.0.1', port=3310, timeout=100)
        return self.clamd_daemon.scan(self.target)





def main():
    target = input('give target:\n')
    scanner = Scanner(clamd.ClamdNetworkSocket(), target)

    print(scanner.single_target())


if __name__ == '__main__':
    main()