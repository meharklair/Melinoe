import random
from datetime import datetime
from colorama import Fore, Style

class Formatting:
    """
    A miscellaneous class for aesthetics
    """
    
    @staticmethod
    def pick_sad_face() -> None:
        faces = ['( ・⌓・｀)', '(つ﹏<。)', '( ཀ ʖ̯ ཀ)', '(っ˘̩╭╮˘̩)っ', 'ಠ╭╮ಠ', '(╥_╥)']
        return random.choice(faces)

    @staticmethod
    def print_banner(version: str) -> None:
        banner = rf"""
        {Fore.RED}
 ______   _______  _______ _________           _________ _______    _______           _______  _______  _        _______  _______ 
(  __  \ (  ____ \(  ___  )\__   __/|\     /|  \__   __/(  ___  )  (  ____ \|\     /|(  ____ )(  ___  )( (    /|(  ___  )(  ____ \
| (  \  )| (    \/| (   ) |   ) (   | )   ( |     ) (   | (   ) |  | (    \/| )   ( || (    )|| (   ) ||  \  ( || (   ) || (    \/
| |   ) || (__    | (___) |   | |   | (___) |     | |   | |   | |  | |      | (___) || (____)|| |   | ||   \ | || |   | || (_____ 
| |   | ||  __)   |  ___  |   | |   |  ___  |     | |   | |   | |  | |      |  ___  ||     __)| |   | || (\ \) || |   | |(_____  )
| |   ) || (      | (   ) |   | |   | (   ) |     | |   | |   | |  | |      | (   ) || (\ (   | |   | || | \   || |   | |      ) |
| (__/  )| (____/\| )   ( |   | |   | )   ( |     | |   | (___) |  | (____/\| )   ( || ) \ \__| (___) || )  \  || (___) |/\____) |
(______/ (_______/|/     \|   )_(   |/     \|     )_(   (_______)  (_______/|/     \||/   \__/(_______)|/    )_)(_______)\_______)

        v{version}{Style.RESET_ALL}
        """
        print(banner)
        print('----------------------------------------------------------------------------------------------------------------------------------')
    @staticmethod
    def print_version(version: str) -> None:
        print(f'v{version}')
    @staticmethod
    def print_separator() -> None:
        print('----------------------------------------------------------------------------------------------------------------------------------')

class Logging:
    """
    Logging functions for logging purposes
    """

    def __init__(self):
        pass

    @staticmethod
    def _get_current_time() -> str:
        return datetime.now().strftime("%H:%M:%S")

    @classmethod
    def okay(cls, message: str) -> None:
        current_time = cls._get_current_time()
        print(f"[{Fore.YELLOW}{current_time}{Style.RESET_ALL}] [{Fore.GREEN}+{Style.RESET_ALL}] {message}")

    @classmethod
    def info(cls, message: str) -> None:
        current_time = cls._get_current_time()
        print(f"[{Fore.YELLOW}{current_time}{Style.RESET_ALL}] [{Fore.BLUE}*{Style.RESET_ALL}] {message}")

    @classmethod
    def warn(cls, message: str) -> None:
        current_time = cls._get_current_time()
        print(f"[{Fore.YELLOW}{current_time}{Style.RESET_ALL}] [{Fore.RED}-{Style.RESET_ALL}] {message}")

    @classmethod
    def misc(cls, message: str) -> None:
        current_time = cls._get_current_time()
        print(f"[{Fore.YELLOW}{current_time}{Style.RESET_ALL}] [{Fore.MAGENTA}~{Style.RESET_ALL}] {message}")

