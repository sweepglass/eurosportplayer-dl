import requests
import json
import base64
from collections import OrderedDict
from Crypto.Cipher import AES
import re
import os

keys_dict = dict()
resolution = "1280x720"

def decryptFile(fn, key, IV, ofn):
    with open(fn, 'rb') as fileh:
        ciphertext = fileh.read()            
    mode = AES.MODE_CBC
    decryptor = AES.new(key, mode, IV=IV)
    plain = decryptor.decrypt(ciphertext)
    with open(ofn, 'wb') as fileh:
        fileh.write(plain)

def unpadBase64(s):
    while s[-1]=='=':
        s = s[:-1]
    return s

def pretty_print_POST(req):
    """
    At this point it is completely built and ready
    to be fired; it is "prepared".

    However pay attention at the formatting used in 
    this function because it is programmed to be pretty 
    printed and may differ from the actual request.
    """
    print('{}\n{}\n{}\n\n{}'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        req.body,
    ))


def getKey(video_url, key_url, authorization):
    okeyfile = "./temp/key.bin"
    headers = {
        'Host':'drm-api.svcs.eurosportplayer.com',
        'authorization':authorization,
        'origin':'https://it.eurosportplayer.com',
        'user-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
        'accept':'*/*',
        'referer':video_url,
        'accept-language':'en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,de;q=0.6,nl;q=0.5,es;q=0.4,ar;q=0.3,pt;q=0.2,fr;q=0.1,ko;q=0.1,sl;q=0.1,cs;q=0.1,fy;q=0.1,tr;q=0.1'
    }
    r = requests.get(key_url, headers=headers)    
    with open(okeyfile, 'wb') as fd:
        for chunk in r.iter_content(chunk_size=128):
            fd.write(chunk)   
    with open(okeyfile, 'rb') as fileh:
        key = fileh.read()
    return key

def downloadFile(url, fn):
    r = requests.get(url)
    with open(fn, 'wb') as fd:
        for chunk in r.iter_content(chunk_size=128):
            fd.write(chunk)
            
            
def procPlaylist(plfn, base_frame_url, access_token):
    framen = 0
    iv = 0
    key = 0
    frames=list()
    
    with open(plfn, "r") as plfh:
        for line in plfh:
            if line.startswith("#EXT-X-KEY:"):
                #print("New key!")
                m = re.search('URI=\"(.+?)\"', line)
                if m:
                    key_url = m.group(1)
                    #print("key_url: "+key_url)
                    if key_url in keys_dict:
                        key = keys_dict[key_url]
                    else:
                        key = getKey(video_url, key_url, access_token)
                        keys_dict[key_url] = key
                        #print("key="+str(key))
                else:
                    print("ERROR: key file not found")
                    
                m = re.search('IV=(.+?)$', line)
                if m:
                    iv_str = m.group(1).replace("0x","")
                    #print("iv_str: "+iv_str)
                    iv = bytes.fromhex(iv_str)
                else:
                    print("ERROR: iv file not found")
                    
            elif not line.startswith("#"):
                #print("New video chunk!")
                frame_url = base_frame_url + line
                frames.append([frame_url, key, iv])

    frame_count = len(frames)
    for framen, frame in enumerate(frames):
        frame_url = frame[0]
        key = frame[1]
        iv = frame[2]
        print("Frame {}/{}".format(framen, frame_count))
        #print("Downloading frame file: "+frame_url)
        out_enc = "./video_enc/"+str(framen)+".ts"
        out_dec = "./video_dec/"+str(framen)+".mp4"
        downloadFile(frame_url, out_enc)
        decryptFile(out_enc, key, iv, out_dec)
        framen += 1



#MAIN
os.makedirs("./temp",exist_ok=True)
os.makedirs("./video_dec", exist_ok=True)
os.makedirs("./video_enc", exist_ok=True)

print("Please insert your eurosportplayer.com credentials")
email=input("Email: ")
password=input("Password: ")

master_url = "https://hlsevent-l3c.ams1.media.eurosportplayer.com/token=exp=1542197105~id=2f50b49c-48d9-4312-84b1-0c9c39b55ff3~hash=ef4cb5a1517a5caee0832ee01fae1cdf8ecfe3ea/ls01/eurosport/event/2018/11/12/VL_Pesaro_Alma_Trieste_DA_20181112_1541974031753/master_desktop_complete-trimmed.m3u8"
video_url = 'https://it.eurosportplayer.com/en/event/vl-pesaro-alma-trieste/8b317d7e-cd3b-471e-804b-128639eae81f'

#*********************************************************#
# 1. Get clientApiKey
#*********************************************************#
print("*"*10+" STEP 1 "+"*"*10)

url="https://it.eurosportplayer.com/en/login"
r = requests.get(url)
pos = r.text.find("clientApiKey")
pos2 = r.text.find(":",pos)
pos3 = r.text.find("\"",pos2)
pos4 = r.text.find("\"",pos3+1)
clientApiKey=r.text[pos3+1:pos4]
print("clientApiKey="+str(clientApiKey))
#clientApiKey=4K0redryzbpsShVgneLaVp9AMh0b0sguXS4CtSuG9dC4vSeo9kzyjCW3mV7jfqPd

print("\n")

#*********************************************************#
# 2. Get access_token
#*********************************************************#

print("*"*10+" STEP 2 "+"*"*10)

headers={
    'Host':'eu.edge.bamgrid.com',
    'origin':'https://it.eurosportplayer.com',
    'x-bamsdk-version':'3.3',
    'authorization':'Bearer '+clientApiKey,
    'content-type':'application/x-www-form-urlencoded',
    'x-bamsdk-platform':'linux',
    'accept':'application/json',
    'user-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
    'referer':'https://it.eurosportplayer.com/en/login',
    'accept-language':'en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,de;q=0.6,nl;q=0.5,es;q=0.4,ar;q=0.3,pt;q=0.2,fr;q=0.1,ko;q=0.1,sl;q=0.1,cs;q=0.1,fy;q=0.1,tr;q=0.1'
}

#Build JWT called "subject_token"

# Important to have an OrderedDict, otherwise the order muight be different and the base64 encoded string might be different
# A string generated from a differently ordered dict will not work (no idea why!!!!!)
st1 = OrderedDict([("typ", "JWT"), ("alg", "HS512")])

#add "separators=(',', ':')", otherwise json.dumps() will include spaces after ':' and after ',', which will alter the base64 string giving a non valid result
st1_str = json.dumps(st1, separators=(',', ':'))
st1_b64 = base64.b64encode(st1_str.encode("utf8")).decode("ascii")
st1_b64 = unpadBase64(st1_b64) #remove "==" at the end, otherwise non-valid result

st2 = OrderedDict([ 
    ("sub", "be517068-f328-4920-aca3-8524c4e3762f"),
    ("aud", "urn:bamtech:service:token"),
    ("nbf", 1541262385),
    ("iss", "urn:bamtech:service:device"),
    ("exp", 2405262385),
    ("iat", 1541262385),
    ("jti", "a3d2cf6d-1119-4758-8727-e1c9cad9bfb0")
    ])
    
st2_str = json.dumps(st2, separators=(',', ':'))
st2_b64 = base64.b64encode(st2_str.encode("ascii")).decode("ascii")
st2_b64 = unpadBase64(st2_b64)

subject_token = st1_b64+"."+st2_b64+"."+"nPmRhQH9RzNF7FQ5QwHGzw-ngEFSIDe75OPXp4eaBiqStsVmJ5WiVGJnTQafEBW1zM1IpOeUvq7YyWpOOzI_fw"

data={
    "grant_type":"urn:ietf:params:oauth:grant-type:token-exchange",
    "latitude":0,
    "longitude":0,
    "platform":"browser",
    "subject_token":subject_token,
    "subject_token_type":"urn:bamtech:params:oauth:token-type:device"
}

url='https://eu.edge.bamgrid.com/token'

r = requests.post(url, headers=headers, data=data)
# Debug
#prepared = r.request
#pretty_print_POST(prepared)

rj = r.json()

with open("step2.json", "w") as fileh:
    json.dump(rj, fileh, sort_keys = True, indent = 4, ensure_ascii = False)
    
access_token = rj['access_token']
print("\n access_token=\""+access_token+"\"\n")

refresh_token = rj['refresh_token']
print("\n refresh_token=\""+refresh_token+"\"\n")

expires_in = rj['expires_in']
print("\n expires_in=\""+str(expires_in)+"\"\n")


#*********************************************************#
# 3. Login (get id_token)
#*********************************************************#

print("*"*10+" STEP 3 "+"*"*10)

url = "https://eu.edge.bamgrid.com/idp/login"

headers={
    'Host':'eu.edge.bamgrid.com',
    'origin':'https://it.eurosportplayer.com',
    'x-bamsdk-version':'3.3',
    'authorization':'Bearer '+access_token,
    'content-type':'application/json; charset=UTF-8',
    'x-bamsdk-platform':'linux',
    'accept':'application/json; charset=utf-8',
    'user-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
    'referer':'https://it.eurosportplayer.com/en/login',
    'accept-language':'en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,de;q=0.6,nl;q=0.5,es;q=0.4,ar;q=0.3,pt;q=0.2,fr;q=0.1,ko;q=0.1,sl;q=0.1,cs;q=0.1,fy;q=0.1,tr;q=0.1' 
}

payload='{"email":"'+email+'","password":"'+password+'"}'

r = requests.post(url, headers=headers,data=payload)
rj = r.json()

with open("step3.json", "w") as fileh:
    json.dump(rj, fileh, sort_keys = True, indent = 4, ensure_ascii = False)

id_token = r.json()['id_token']
print("id_token="+id_token)
print("\n")

#*********************************************************#
# 4. Login (get assertion)
#*********************************************************#

print("*"*10+" STEP 4 "+"*"*10)

url="https://eu.edge.bamgrid.com/accounts/grant"

headers={
    'Host':'eu.edge.bamgrid.com',
    'origin':'https://it.eurosportplayer.com',
    'x-bamsdk-version':'3.3',
    'authorization':'Bearer '+access_token,
    'content-type':'application/json; charset=UTF-8',
    'x-bamsdk-platform':'linux',
    'accept':'application/json; charset=utf-8',
    'user-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
    'referer':'https://it.eurosportplayer.com/en/login',
    'accept-language':'en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,de;q=0.6,nl;q=0.5,es;q=0.4,ar;q=0.3,pt;q=0.2,fr;q=0.1,ko;q=0.1,sl;q=0.1,cs;q=0.1,fy;q=0.1,tr;q=0.1' 
}

data='{"id_token":"'+id_token+'"}'

r = requests.post(url, headers=headers,data=data)
rj = r.json()

with open("step4.json", "w") as fileh:
    json.dump(rj, fileh, sort_keys = True, indent = 4, ensure_ascii = False)

assertion = r.json()['assertion']
print("assertion="+assertion)
print("\n")

#*********************************************************#
# 5. Get access_token
#*********************************************************#

print("*"*10+" STEP 5 "+"*"*10)

url='https://eu.edge.bamgrid.com/token'

headers = {
    'Host':'eu.edge.bamgrid.com',
    'origin':'https://it.eurosportplayer.com',
    'x-bamsdk-version':'3.3',
    'authorization':'Bearer 4K0redryzbpsShVgneLaVp9AMh0b0sguXS4CtSuG9dC4vSeo9kzyjCW3mV7jfqPd',
    'content-type':'application/x-www-form-urlencoded',
    'x-bamsdk-platform':'linux',
    'accept':'application/json',
    'user-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
    'referer':'https://it.eurosportplayer.com/en/login',
    'accept-language':'en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,de;q=0.6,nl;q=0.5,es;q=0.4,ar;q=0.3,pt;q=0.2,fr;q=0.1,ko;q=0.1,sl;q=0.1,cs;q=0.1,fy;q=0.1,tr;q=0.1'
}

data = {
    "grant_type":"urn:ietf:params:oauth:grant-type:token-exchange",
    "latitude":0,
    "longitude":0,
    "platform":"browser",
    "subject_token":assertion,
    "subject_token_type":"urn:bamtech:params:oauth:token-type:account"
}

r = requests.post(url, headers=headers, data=data)
# Debug
#prepared = r.request
#pretty_print_POST(prepared)

rj = r.json()

with open("step5.json", "w") as fileh:
    json.dump(rj, fileh, sort_keys = True, indent = 4, ensure_ascii = False)
    
access_token = rj['access_token']
print("\n access_token=\""+access_token+"\"\n")

refresh_token = rj['refresh_token']
print("\n refresh_token=\""+refresh_token+"\"\n")

expires_in = rj['expires_in']
print("\n expires_in=\""+str(expires_in)+"\"\n")

#*********************************************************#
# 7. Download playlist
#*********************************************************#

print("*"*10+" STEP 6 "+"*"*10)

master_file = "master.m3u8"
downloadFile(master_url, master_file)
with open(master_file, "r") as fileh:
    for line in fileh:
        if line.startswith("#EXT-X-STREAM-INF:RESOLUTION="+resolution):
            print("resolution found!")
            
            remote_file = fileh.readline()
            print("Remote playlist file: "+remote_file)
            playlist_url = master_url.replace("master_desktop_complete-trimmed.m3u8","") + remote_file

            local_file = "frames.m3u8"
            if os.path.isfile(local_file):
                os.remove(local_file)
            downloadFile(playlist_url, local_file)
            
            frame_baseurl = master_url.replace("master_desktop_complete-trimmed.m3u8","") + remote_file[:remote_file.find("/")+1]
            print("frame_baseurl="+frame_baseurl)
            procPlaylist(local_file, frame_baseurl, access_token)


