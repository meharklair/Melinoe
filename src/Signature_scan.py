import os
import time
import click
import urllib.request
import zipfile
from logging.logging import Logging, Formatting

log = Logging()
fmt = Formatting()
current_version = "0.1.1" 

class Scanner:
    """
    Main scanning component of the program
    """

    def __init__ (self, target_path, database):
        self.database = database
        self.target_path = target_path

    def download_database(self):
        # add timing of how long the compilation took
        urllib.request.urlretrieve("https://bazaar.abuse.ch/export/txt/sha256/full/", "Database_file/database.zip")
        self.unzip()

    def unzip(self):
        with zipfile.ZipFile('Database_file/database.zip', 'r') as zip_ref:
            zip_ref.extractall('Database_file')

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

    scanner = Scanner(directory, None)
    scanner.download_database()
     

if __name__ == '__main__':
    main()
