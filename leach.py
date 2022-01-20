# in the name of null...!
import requests
from time import sleep
import json
import os
from threading import Thread
urlauth = "https://api.divar.ir/v5/auth/authenticate"
urlauthconfirm = "https://api.divar.ir/v5/auth/confirm"
banner = """
_   _                 _
| \ | |_   _ _ __ ___ | |__   ___ _ __
|  \| | | | | '_ ` _ \| '_ \ / _ \ '__|
| |\  | |_| | | | | | | |_) |  __/ |
|_| \_|\__,_|_| |_| |_|_.__/ \___|_|

 _                    _                   _
| |    ___  __ _  ___| |__   ___ _ __    | |
| |   / _ \/ _` |/ __| '_ \ / _ \ '__|   | |
| |__|  __/ (_| | (__| | | |  __/ | _ _ _|_|
|_____\___|\__,_|\___|_| |_|\___|_|(_|_|_|_)
"""
def print_slow(text):
    for x in text:
        print(x , end="" , flush=True)
        sleep(.01)
def auth():
    phone = input("┌──(Number_Leacher)-[ٍ Enter Phone Number [090xxxxxxxx] : ]\n└─$ ")
    rauth = requests.post(urlauth , json={"phone":phone})
    print(rauth.status_code)
    if os.path.exists("token.txt") == False:
            fc = open("token.txt" , "x")
    try:
        if (rauth.status_code == 200):
            print("\n")
            print_slow("Verification Code Was Send...!")
            print("\n")
            vcode = input("┌──(Number_Leacher)-[ٍ Enter The Verification Code : ]\n└─$")
            rvcode = requests.post(urlauthconfirm , json={"phone":phone,"code":vcode})
            print("\n","status code : ",rvcode.status_code)
            if (rvcode.status_code == 200):
                print_slow("Authentication Successfully...!")
                F = open("token.txt" , "w")
                auth = json.loads(rvcode.content)
                F.write(str(auth["token"]))
                F.close()
    except Exception as err:
        print(err)
states = ["tehran" , "isfahan" , "shiraz" , "karaj" , "mashhad" , "tabriz"]
category = ["real-estate" , "vehicles" , "electronic-devices" , "home-kitchen" , "services" , "personal-goods" , "entertainment" , "social-services" , "tools-materials-equipment" , "jobs"]

def header(token , state):
    global HED
    HED = {
"Accept":"application/json, text/plain, */*",
"Accept-Encoding":"gzip, deflate, br",
"Accept-Language":"en-US,en;q=0.5",
"Authorization":f"Basic {token}",
"Sec-Fetch-Dest":"empty",
"Sec-Fetch-Mode":"cors",
"Sec-Fetch-Site":"same-site",
"TE":"trailers",
"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
}
    return HED

def divar(sha , m):
    global tkn
    re = requests.get("https://api.divar.ir/v8/web-search/{}/{}".format(sha , m))
    resp = re.text
    res = json.loads(resp)
    for k in range(23):
        tkn = res["widget_list"][k]["data"]["token"]
        def leach():
            req = requests.get("https://api.divar.ir/v5/posts/{}/contact".format(tkn), headers=HED)
            reqs = req.text
            respq = json.loads(reqs)
            if req.status_code == 200:
                p = respq["widgets"]["contact"]["phone"]
                if "09" in p:
                    print(p)
            else:
                if req.status_code == 429:
                    print("You Are Limited...! Status Code : " , req.status_code)
                elif req.status_code == 401:
                    print("Auth Error...! \nPlease Remove Token.txt File And Restart The Script :)")
                
        t1 = Thread(target=leach())
        t1.start()
        
def main():
    global sss , cat
    sys=os.uname()
    if os.uname()[0] == "Linux":
        os.system("clear")
        os.system("resize -s 30 150")
        
    else:
        os.system("clr")
    print_slow(banner)
    sleep(1)
    print("\n")
    print_slow("CoDDeD By Null...!")
    print("\n")
    print_slow("Number Leacher :")
    print("\n")
    i = 1
    for x in range(0 , len(states)):
        print(i , ">" , states[x])
        i = i+1
    sss = input("┌──(Number_Leacher)-[ٍ Enter The State Number : ]\n└─$ ")
    FileToken = open("token.txt" , "r")
    t = FileToken.read()
    header(t , states[int(sss) - 1])
    print("\n")
    kl = 1
    for ii in range(0 , len(category)):
        print(kl , ">" , category[ii])
        kl = kl + 1
    cat = input("┌──(Number_Leacher)-[ٍ Enter The Category Number : ]\n└─$ ")
        
def run():
    if os.path.exists("token.txt") == False:
        ac = input("┌──(Number_Leacher)-[You Are Not Authentication...!\nDo You Want Authentication Now ? [ Y ; N ] : ]\n└─$ ")
        if ac == "Y":
            auth()
            main()
            print_slow("Please Wait...\nCoDDeD By Null...!\n")
            divar(states[int(sss) - 1],category[int(cat) - 1])
        elif ac == "y":
            auth()
            main()
            print_slow("Please Wait...\nCoDDeD By Null...!\n")
            divar(states[int(sss) - 1],category[int(cat) - 1])
        
    elif os.path.exists("token.txt") == True:
        main()
        print_slow("Please Wait...\nCoDDeD By Null...!\n")
        divar(states[int(sss) - 1],category[int(cat) - 1])
    else:
        print_slow("Operation Canceled By User...!")
        print("\n")
run()