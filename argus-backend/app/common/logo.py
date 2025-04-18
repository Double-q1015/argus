import sys
import os
import random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.config import settings

def logo():
    logos = ("""
        ▄▖        
        ▌▌▛▘▛▌▌▌▛▘
        ▛▌▌ ▙▌▙▌▄▌
            ▄▌    
    """,
    """
        ▄▄▄       ██▀███    ▄████  █    ██   ██████ 
        ▒████▄    ▓██ ▒ ██▒ ██▒ ▀█▒ ██  ▓██▒▒██    ▒ 
        ▒██  ▀█▄  ▓██ ░▄█ ▒▒██░▄▄▄░▓██  ▒██░░ ▓██▄   
        ░██▄▄▄▄██ ▒██▀▀█▄  ░▓█  ██▓▓▓█  ░██░  ▒   ██▒
        ▓█   ▓██▒░██▓ ▒██▒░▒▓███▀▒▒▒█████▓ ▒██████▒▒
        ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ░▒   ▒ ░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░
        ▒   ▒▒ ░  ░▒ ░ ▒░  ░   ░ ░░▒░ ░ ░ ░ ░▒  ░ ░
        ░   ▒     ░░   ░ ░ ░   ░  ░░░ ░ ░ ░  ░  ░  
            ░  ░   ░           ░    ░           ░  
    """
            )
    print(random.choice(logos))
    print()
    print(f" Argus {settings.VERSION}")
    print()
    print(" Github: https://github.com/argus-security")
    print()
    sys.stdout.flush()

if __name__ == "__main__":
    logo()
