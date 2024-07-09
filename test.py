import sys
import requests

from burp_config import BurpConfig


if __name__ == "__main__":
    burp = BurpConfig(sys.argv[1])
    burp.on()
    response = requests.get("https://www.google.com")
    burp.off()
    response = requests.get("https://www.google.com")



