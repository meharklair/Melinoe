import os
import time
import click
import urllib.request
import zipfile
import hashlib
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
        log.info('Attempting to download database zip...')
        
        start = time.perf_counter()
        urllib.request.urlretrieve("https://bazaar.abuse.ch/export/txt/sha256/full/","src\Database\database.zip")
        self.unzip()
        end = time.perf_counter()
        
        log.info(f'Download completed in {round(end - start, 9)} seconds!')


    def unzip(self):
        log.info('Extracting database zip..')
        with zipfile.ZipFile('src\Database\database.zip', 'r') as zip_ref:
            zip_ref.extractall('src\Database')
        log.info('Successfully extracted!!')
            
            
    def compute_file_hash(self, file_path, algorithm='sha256'):
        """Compute the hash of a file using the specified algorithm."""
        hash_func = hashlib.new(algorithm)
    
        with open(file_path, 'rb') as file:
        # Read the file in chunks of 8192 bytes
            while chunk := file.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    
    
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
        sha256_hash = self.compute_file_hash(target) + '\n'
        with open("src\\Database\\full_sha256.txt",'r') as file:
            data_base = file.readlines()
            if sha256_hash in data_base:
                log.okay(f'MALWARE DETECTED! "{target}" matched malware signature -> {sha256_hash} {fmt.pick_sad_face()}')

    def scan_directory(self):
        # https://stackoverflow.com/questions/16953842/using-os-walk-to-recursively-traverse-directories-in-python
        for root, dirs, files in os.walk(self.target_path):
            path = root.split(os.sep)
            # print((len(path) - 1) * '---', os.path.basename(root))
            for file in files:
               # print(len(path) * '---', file)
                full_path = os.path.join(root,file)
                self.scan_single(full_path)



@click.command(no_args_is_help = False)
@click.option("-v", "--version", is_flag=True, help="The current version.", required=False)
@click.option("-f", "--file", help="The YARA rule file with which to scan", required=False)
@click.option("-d", "--directory", help="The directory you wish to scan", default=".", required=False)

def main(version, file, directory) -> None:

    scanner = Scanner(directory, None)
    scanner.download_database()
    scanner.scan_target()
     

if __name__ == '__main__':
    main()
