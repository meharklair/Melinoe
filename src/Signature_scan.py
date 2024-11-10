import os
import time
import click
import urllib.request
import zipfile
import hashlib
import datetime
from logging.logging import Logging, Formatting

log = Logging()
fmt = Formatting()
current_version = "0.1.1" 

class Scanner:
    """
    Main scanning component of the program
    """

    def __init__ (self, target_path, database, write):
        self.database = database
        self.target_path = target_path
        self.write = write

    def download_database(self):
        log.info('Attempting to download database zip...')
        start = time.perf_counter()
        urllib.request.urlretrieve("https://bazaar.abuse.ch/export/txt/sha256/full/","src\\Database\\database.zip")
        self.unzip()
        end = time.perf_counter()
        log.info(f'Download completed in {round(end - start, 9)} seconds!')

    def check_download(self):
        """Checks if the file is older than the update time of the database"""
        path = "src\\Database\\full_sha256.txt"
        ti_m = os.path.getmtime(path)
        mod_time = datetime.datetime.fromtimestamp(ti_m)
        now = datetime.datetime.now()
        # this is an hour because malware bazaar only updates their files once every hour
        hour = datetime.timedelta(hours = 1)
        time_diff = now - mod_time
        if (time_diff < hour):
             log.info('Database is up to date!')
             log.info('Skipping download...')
             return True
        return False
             

    def unzip(self):
        log.info('Extracting zip...')
        with zipfile.ZipFile('src\\Database\\database.zip', 'r') as zip_ref:
            zip_ref.extractall('src\\Database')
        log.info('Successfully extracted!!')
            
            
    def compute_file_hash(self, file_path, algorithm='sha256'):
        """Compute the hash of a file using the specified algorithm."""
        hash_func = hashlib.new(algorithm)
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    
    
    def scan_target(self):
        """Scans the target by either doing a single target scan or a direcotry scan."""
        counter = 0
        log.info('Beginning scan...')
        start = time.perf_counter()
        with open("src\\Database\\full_sha256.txt",'r') as file:
            database = file.readlines()
        if (os.path.isfile(self.target_path)):
           counter = self.scan_single(self.target_path, database, counter)
        elif (os.path.isdir(self.target_path)):
           counter = self.scan_directory(database, counter)
        else:
            log.warn('Target file or folder does not exist, exiting...')
            exit()
        end = time.perf_counter()
        if counter == 0:
            if self.write:
                    f = open("scan_results\\results.txt", "a",  encoding="utf-8")
                    f.write(f'No Malware Found (＾▽＾)!!!!\n')
                    f.close()
            log.okay(f'No Malware Found (＾▽＾)!!!!')
        log.info(f'Scan completed in {round(end - start, 9)} seconds!')
        log.misc('I am time itself. What are you?')
        
        
    def scan_single(self, target, database, counter):
        sha256_hash = self.compute_file_hash(target) + '\n'
        if sha256_hash in database:
            counter += 1
            if self.write:
                f = open("scan_results\\results.txt", "a",  encoding="utf-8")
                f.write(f'MALWARE DETECTED! "{target}" matched malware signature -> {sha256_hash.strip()} {fmt.pick_sad_face()}\n')
                f.close()
            log.okay(f'MALWARE DETECTED! "{target}" matched malware signature -> {sha256_hash.strip()} {fmt.pick_sad_face()}')
        return counter

    def scan_directory(self, database, counter):
        # Stack Overflow; User: Ajay; This code is for recursing through a directory
        for root, dirs, files in os.walk(self.target_path):
            path = root.split(os.sep)
            for file in files:
                full_path = os.path.join(root,file)
                counter = self.scan_single(full_path, database, counter)
        return counter


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
