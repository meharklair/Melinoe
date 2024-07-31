from datetime import datetime
from colorama import Fore, Style

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
        print(f"[ {Fore.YELLOW}{current_time}{Style.RESET_ALL} ] [ {Fore.GREEN}+{Style.RESET_ALL} ] {message}")

    @classmethod
    def info(cls, message: str) -> None:
        current_time = cls._get_current_time()
        print(f"[ {Fore.YELLOW}{current_time}{Style.RESET_ALL} ] [ {Fore.BLUE}*{Style.RESET_ALL} ] {message}")

    @classmethod
    def warn(cls, message: str) -> None:
        current_time = cls._get_current_time()
        print(f"[ {Fore.YELLOW}{current_time}{Style.RESET_ALL} ] [ {Fore.RED}-{Style.RESET_ALL} ] {message}")

    @classmethod
    def misc(cls, message: str) -> None:
        current_time = cls._get_current_time()
        print(f"[ {Fore.YELLOW}{current_time}{Style.RESET_ALL} ] [ {Fore.MAGENTA}~{Style.RESET_ALL} ] {message}")

