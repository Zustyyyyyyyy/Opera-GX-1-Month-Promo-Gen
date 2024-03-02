import tls_client
import requests
import secrets
import yaml
import random
import threading
import sys
import time
import concurrent.futures

from tls_client.exceptions import TLSClientExeption
from colorama import Fore, Style

user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0"
thread_lock = threading.Lock()
with open("proxies.txt", "r") as file:
    proxies = file.read().splitlines()
with open("config.yml", "r") as file:
    config = yaml.safe_load(file.read())

class Utils:

    @staticmethod
    def solve_recaptcha():
        task_payload = {
            "clientKey": config["capsolver-api-key"],
            "task": {
                "type": "ReCaptchaV2TaskProxyLess",
                "websiteURL": "https://auth.opera.com",
                "websiteKey": "6LdYcFgaAAAAAEH3UnuL-_eZOsZc-32lGOyrqfA4",
                "isInvisible": True,
                "userAgent": user_agent
            }
        }

        response = requests.post("https://api.capsolver.com/createTask", json=task_payload)
        if response.status_code == 200:
            task_id = response.json()["taskId"]
        else:
            raise Exception("Failed to create captcha task.")

        while True:
            response = requests.post("https://api.capsolver.com/getTaskResult", json={"clientKey": config["capsolver-api-key"], "taskId": task_id})
            if "ready" in response.text:
                return response.json()["solution"]["gRecaptchaResponse"]
            elif "processing" in response.text:
                time.sleep(1)
            else:
                raise Exception("Failed to solve captcha.")


class Logger:
    @staticmethod
    def info(content):
        message = f'{Fore.GREEN}{Style.BRIGHT}[+]{Style.RESET_ALL} {Fore.RESET}{content}{Fore.RESET}'
        sys.stdout.write(message + "\n")

    @staticmethod
    def error(content):
        message = f'{Fore.RED}{Style.BRIGHT}[!]{Style.RESET_ALL} {Fore.RESET}{content}{Fore.RESET}'
        sys.stdout.write(message + "\n")


class GeneratePromo:

    def __init__(self):
        self.email = str()
        self.password = str()
        self.session = tls_client.Session(
            client_identifier="opera_107",
            random_tls_extension_order=True
        )
        self.session.timeout_seconds = 5
        if config["proxies"] and proxies:
            proxy = random.choice(proxies)
            self.session.proxies = {
                "http": f"http://{proxy}",
                "https": f"http://{proxy}"
            }

        self.post_headers = {
            "Accept": "application/json",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Content-Type": "application/json",
            "Origin": "https://auth.opera.com",
            "Referer": "https://auth.opera.com/account/authenticate/signup",
            "Sec-Ch-Ua": '"Not A(Brand";v="99", "Opera";v="107", "Chromium";v="121"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"macOS"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": user_agent,
            "X-Language-Locale": "en"
        }

        self.get_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Referer": "https://auth.opera.com/account/authenticate/success",
            "Sec-Ch-Ua": '"Not A(Brand";v="99", "Opera";v="107", "Chromium";v="121"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"macOS"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": user_agent
        }


    def signup(self, solution, tries=1):
        if tries > 15:
            raise Exception("Failed to create account.")

        self.email = f"{secrets.token_hex(6)}@gmail.com"
        self.password = secrets.token_hex(8)

        payload = {
            "email": self.email,
            "password": self.password,
            "marketing_consent": False,
            "password_repeated": self.password,
            "services": ["gmx", "opera_desktop"],
            "captcha": solution
        }

        try:
            response = self.session.post("https://auth.opera.com/account/v4/api/signup", headers=self.post_headers, json=payload)
        except TLSClientExeption:
            return self.signup(solution, tries + 1)

        if response.status_code == 429:
            raise Exception("Rate limited.")

        if response.status_code == 200:
            self.post_headers["X-Csrftoken"] = response.headers["X-Opera-Csrf-Token"]
            self.session.patch("https://auth.opera.com/api/v1/profile", headers=self.post_headers, json={"username": secrets.token_hex(6)})
        else:
            raise Exception("Failed to create account.")

    def login(self, tries=1):
        if tries > 15:
            raise Exception("Failed to get session token.")
        try:
            self.session.get("https://api.gx.me/session/login?site=gxme&target=%2F", headers=self.get_headers)
            response = self.session.get("https://api.gx.me/oauth2/authorization/opera", headers=self.get_headers)
            location = response.headers["Location"]

            response = self.session.get(location, headers=self.get_headers)
            new_location = response.headers["Location"]
            self.session.get(new_location, headers=self.get_headers)

            response = self.session.get("https://auth.opera.com/account/login-redirect?service=gmx", headers=self.get_headers)
            authorize_location = response.headers["Location"]

            response = self.session.get(authorize_location, headers=self.get_headers)
            login_location = response.headers["Location"]

            response = self.session.get(login_location, headers=self.get_headers)
        except TLSClientExeption:
            return self.login(tries + 1)

        self.session.cookies = response.cookies
        self.session.cookies.set(
            name="SESSION_TYPE",
            value="user"
        )

    def pull_promo(self, tries=1):
        if tries > 15:
            raise Exception("Failed to pull promo.")

        headers = {
            "Accept": "application/json",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Origin": "https://www.opera.com",
            "Referer": "https://www.opera.com",
            "Sec-Ch-Ua": '"Not A(Brand";v="99", "Opera";v="107", "Chromium";v="121"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"macOS"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "cross-site",
            "User-Agent": user_agent
        }
        try:
            response = self.session.get("https://api.gx.me/profile/token", headers=headers)
            headers.update({
                "Authorization": response.json()["data"]
            })
            self.session.cookies.clear()

            response = self.session.post("https://discord.opr.gg/v2/direct-fulfillment", headers=headers)
            token = response.json()["token"]

        except TLSClientExeption:
            return self.pull_promo(tries + 1)

        thread_lock.acquire()
        with open("./output/promos.txt", "a") as f:
            f.write(
                f"https://discord.com/billing/partner-promotions/1180231712274387115/{token}\n"
            )
        thread_lock.release()



# -- Main --

def generate_promo():
    try:
        gen = GeneratePromo()
        solution = Utils.solve_recaptcha()
        gen.signup(solution)
        Logger.info(f"Successfully generated OperaGX account | Email: {gen.email}")
        gen.login()
        gen.pull_promo()
        Logger.info(f"Successfully pulled promo link | Email: {gen.email}")
    except Exception as e:
        Logger.error(f"{str(e)}")


with concurrent.futures.ThreadPoolExecutor(max_workers=config["threads"]) as executor:
    while True:
        executor.submit(generate_promo)
