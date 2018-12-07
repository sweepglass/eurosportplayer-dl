import requests
import json
import base64
from collections import OrderedDict
from Crypto.Cipher import AES
import re
import os
import urllib
import time
import argparse
import multiprocessing as mp
from multiprocessing import Value, Lock
import sys
import shutil
import jsonpickle

# Global variables
frames_counter_pool = None
frames_count_pool = None
keys_dict = dict()
frames_count = 0
user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36'
debug = False
verbose = False
list_fileh = None

class Counter(object):
    def __init__(self, initval=0):
        self.val = Value('i', initval)
        self.lock = Lock()

    def increment(self):
        with self.lock:
            self.val.value += 1
        return self

    def value(self):
        with self.lock:
            return self.val.value

def lookahead_line(fileh):
    line = fileh.readline()
    count = len(line) + 1
    fileh.seek(-count, 1)
    return fileh, line

def getVideoMetadata(esp_url, authorization, title, contentID):
    headers = {
        'Host':'search-api.svcs.eurosportplayer.com',
        'x-bamsdk-version':'3.3',
        'accept':'application/json',
        'x-bamsdk-platform':'linux',
        'origin':'https://it.eurosportplayer.com',
        'authorization':'Bearer '+authorization,
        'user-agent':user_agent,
        'referer':esp_url,
        'accept-language':'en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,de;q=0.6,nl;q=0.5,es;q=0.4,ar;q=0.3,pt;q=0.2,fr;q=0.1,ko;q=0.1,sl;q=0.1,cs;q=0.1,fy;q=0.1,tr;q=0.1'
    }

    url='https://search-api.svcs.eurosportplayer.com/svc/search/v2/graphql/persisted/query/eurosport/Airings'

    data = {
        "preferredLanguages":["en","it"],
        "mediaRights":["GeoMediaRight"],
        "uiLang":"en",
        "include_images":1,
        "pageType":"event",
        "title":title,
        "contentId":contentID
    }

    data_str = json.dumps(data, separators=(',', ':'))
    if verbose:
        print("data_str='"+data_str+"'")
    data_enc = urllib.parse.quote_plus(data_str)
    if verbose:
        print("data_enc='"+data_enc+"'")

    r = requests.get(url, headers=headers, params="variables="+data_str)
    if debug:
        pretty_print_POST(r.request)
        print(r.text)
    rj = r.json()

    with open("./download/metadata.json","w") as fileh:
        fileh.write(json.dumps(rj, sort_keys=True, indent="\t"))

    eventId = rj['data']['Airings'][0]['eventId']

    mediaId = rj['data']['Airings'][0]['mediaId']

    titles = rj['data']['Airings'][0]['titles'][0]

    episode_name = titles['episodeName']
    title = titles['title']

    if debug:
        print("eventId='"+eventId+"'")
        print("mediaId='"+mediaId+"'")

    return {'eventId':eventId, 'mediaId':mediaId, 'episodeName':episode_name, 'title':title}

def getMasterFile(esp_url, metadata, authorization):

    mediaId = metadata['mediaId']

    headers={
        'Host':'global-api.svcs.eurosportplayer.com',
        'x-bamsdk-version':'3.3',
        'accept':'application/vnd.media-service+json; version=2',
        'x-bamsdk-platform':'linux',
        'origin':'https://it.eurosportplayer.com',
        'authorization':authorization,
        'user-agent':user_agent,
        'referer':esp_url,
        'accept-language':'en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,de;q=0.6,nl;q=0.5,es;q=0.4,ar;q=0.3,pt;q=0.2,fr;q=0.1,ko;q=0.1,sl;q=0.1,cs;q=0.1,fy;q=0.1,tr;q=0.1'
    }

    url='https://global-api.svcs.eurosportplayer.com/media/'+mediaId+'/scenarios/browser'

    r = requests.get(url, headers=headers)
    rj = r.json()
    #print(rj)
    return rj['stream']['complete']

def decryptStream(ciphertext, key, IV, ofn):
    mode = AES.MODE_CBC
    #print("New AES: '{}', '{}', '{}'".format(key,mode,IV))
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


def getKey(esp_url, key_url, authorization):
    headers = {
        'Host':'drm-api.svcs.eurosportplayer.com',
        'authorization':authorization,
        'origin':'https://it.eurosportplayer.com',
        'user-agent':user_agent,
        'accept':'*/*',
        'referer':esp_url,
        'accept-language':'en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,de;q=0.6,nl;q=0.5,es;q=0.4,ar;q=0.3,pt;q=0.2,fr;q=0.1,ko;q=0.1,sl;q=0.1,cs;q=0.1,fy;q=0.1,tr;q=0.1'
    }
    r = requests.get(key_url, headers=headers, stream=True)
    return r.content

def downloadFile(url, fn):
    r = requests.get(url)
    with open(fn, 'wb') as fd:
        for chunk in r.iter_content(chunk_size=128):
            fd.write(chunk)


def downloadFileRaw(url):
    if verbose:
        print("requests.get")
    r = requests.get(url, stream=True)
    if verbose:
        print("r.content")
    cont = r.content
    return cont


def procPlaylist(esp_url, plfn, base_frame_url, access_token, args, frames_counter):

    iv = 0
    key = 0
    frames=list()
    framen = 0

    # Build list of files
    with open(plfn, "r") as plfh:
        for line in plfh:
            if line.find("404 Not Found") != -1:
                print("ERROR: stream not found!")
                exit()

            # Decryption key found
            if line.startswith("#EXT-X-KEY:"):
                m = re.search('URI=\"(.+?)\"', line)
                if m:
                    key_url = m.group(1)
                    #print("key_url: "+key_url)
                    if key_url in keys_dict:
                        key = keys_dict[key_url]
                    else:
                        key = getKey(esp_url, key_url, access_token)
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

            # Video frame found
            elif not line.startswith("#"):
                out_dec = "./download/videos/"+str(framen)+".mp4"
                if os.path.isfile(out_dec):
                    if args.continuedown:
                        print("Skipping frame {} (--continue argument passed)".format(framen))
                        frames_counter.increment()
                    else:
                        print("ERROR: frame already present and --continue argument was not passed. This should not happen!")
                        exit()
                else:
                    #add the frame to the list of frames to download
                    frame_url = base_frame_url + line
                    frames.append([frame_url, key, iv, framen])
                framen += 1 #increase frame number in any case, also if we skipped the frame

    return frames

def init_creator_pool(counter, count):
    global frames_counter_pool
    frames_counter_pool = counter

    global frames_count_pool
    frames_count_pool = count

def downloadVideoFrame(frame_data):
    global frames_count_pool
    global frames_counter_pool
    global list_fileh

    frame_url = frame_data[0]
    key = frame_data[1]
    iv = frame_data[2]
    framen = frame_data[3]

    out_dec = "./download/videos/"+str(framen)+".mp4"

    #print("Downloading frame {}/{} (total downloaded {} - {:.2%})".format(framen, frames_count_pool, frames_counter_n, frames_counter_n/frames_count_pool))
    fcont=downloadFileRaw(frame_url)
    if debug:
        print("Decrypting...")
    decryptStream(fcont, key, iv, out_dec)

    counter_n = frames_counter_pool.increment().value()

    perc = counter_n / frames_count_pool
    done = int(50 * perc)
    sys.stdout.write("\r[{}{}] {:.2%} ({}/{})".format('=' * done, ' ' * (50-done), perc, counter_n, frames_count_pool))
    sys.stdout.flush()

    list_fileh.write("file \"./videos/" + str(framen) + ".mp4\"\n")
    list_fileh.flush()

def getClientApiKey():
    url="https://it.eurosportplayer.com/en/login"
    r = requests.get(url)
    pos = r.text.find("clientApiKey")
    pos2 = r.text.find(":",pos)
    pos3 = r.text.find("\"",pos2)
    pos4 = r.text.find("\"",pos3+1)
    client_api_key=r.text[pos3+1:pos4]
    if verbose:
        print("clientApiKey="+str(clientApiKey))
        #clientApiKey=4K0redryzbpsShVgneLaVp9AMh0b0sguXS4CtSuG9dC4vSeo9kzyjCW3mV7jfqPd
        print("\n")
    return client_api_key

def getAnonymAccessToken(client_api_key, user_agent):
    headers={
        'Host':'eu.edge.bamgrid.com',
        'origin':'https://it.eurosportplayer.com',
        'x-bamsdk-version':'3.3',
        'authorization':'Bearer '+client_api_key,
        'content-type':'application/x-www-form-urlencoded',
        'x-bamsdk-platform':'linux',
        'accept':'application/json',
        'user-agent':user_agent,
        'referer':'https://it.eurosportplayer.com/en/login',
        'accept-language':'en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,de;q=0.6,nl;q=0.5,es;q=0.4,ar;q=0.3,pt;q=0.2,fr;q=0.1,ko;q=0.1,sl;q=0.1,cs;q=0.1,fy;q=0.1,tr;q=0.1'
    }

    #Build JWT called "subject_token"

    # Important to have an OrderedDict, otherwise the order might be different and the base64 encoded string might be different
    # A string generated from a differently ordered dict will not work (no idea why!!!!!)
    st1 = OrderedDict([("typ", "JWT"), ("alg", "HS512")])

    #add "separators=(',', ':')", otherwise json.dumps() will include spaces after ':' and after ',', which will alter the base64 string giving a non valid result
    st1_str = json.dumps(st1, separators=(',', ':'))
    st1_b64 = base64.b64encode(st1_str.encode("utf8")).decode("ascii")
    #remove "==" at the end, which is used to pad a base64 into 64bit. Leaving == at the end would make the server reject the request
    st1_b64 = unpadBase64(st1_b64)

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

    if debug:
        with open("step2.json", "w") as fileh:
            json.dump(rj, fileh, sort_keys = True, indent = 4, ensure_ascii = False)

    access_token = rj['access_token']
    refresh_token = rj['refresh_token']
    expires_in = rj['expires_in']

    return access_token, refresh_token, expires_in

def getAuthIdToken(access_token, user_agent, email, password):
        url = "https://eu.edge.bamgrid.com/idp/login"

        headers={
            'Host':'eu.edge.bamgrid.com',
            'origin':'https://it.eurosportplayer.com',
            'x-bamsdk-version':'3.3',
            'authorization':'Bearer '+access_token,
            'content-type':'application/json; charset=UTF-8',
            'x-bamsdk-platform':'linux',
            'accept':'application/json; charset=utf-8',
            'user-agent':user_agent,
            'referer':'https://it.eurosportplayer.com/en/login',
            'accept-language':'en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,de;q=0.6,nl;q=0.5,es;q=0.4,ar;q=0.3,pt;q=0.2,fr;q=0.1,ko;q=0.1,sl;q=0.1,cs;q=0.1,fy;q=0.1,tr;q=0.1'
        }

        payload='{"email":"'+email+'","password":"'+password+'"}'

        r = requests.post(url, headers=headers,data=payload)
        rj = r.json()

        if debug:
            with open("step3.json", "w") as fileh:
                json.dump(rj, fileh, sort_keys = True, indent = 4, ensure_ascii = False)

        id_token = r.json()['id_token']
        return id_token

def getAuthAssertion(access_token, user_agent, id_token):
    url="https://eu.edge.bamgrid.com/accounts/grant"

    headers={
        'Host':'eu.edge.bamgrid.com',
        'origin':'https://it.eurosportplayer.com',
        'x-bamsdk-version':'3.3',
        'authorization':'Bearer '+access_token,
        'content-type':'application/json; charset=UTF-8',
        'x-bamsdk-platform':'linux',
        'accept':'application/json; charset=utf-8',
        'user-agent':user_agent,
        'referer':'https://it.eurosportplayer.com/en/login',
        'accept-language':'en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,de;q=0.6,nl;q=0.5,es;q=0.4,ar;q=0.3,pt;q=0.2,fr;q=0.1,ko;q=0.1,sl;q=0.1,cs;q=0.1,fy;q=0.1,tr;q=0.1'
    }

    #uses the id_token (obtained by logging in)
    data = '{"id_token":"' + id_token + '"}'

    r = requests.post(url, headers=headers,data=data)
    rj = r.json()

    if debug:
        with open("step4.json", "w") as fileh:
            json.dump(rj, fileh, sort_keys = True, indent = 4, ensure_ascii = False)

    assertion = r.json()['assertion']
    if verbose:
        print("assertion="+assertion)
        print("\n")

    return assertion

def getAuthAccessToken(client_api_key, user_agent, assertion):
    url='https://eu.edge.bamgrid.com/token'

    headers = {
        'Host':'eu.edge.bamgrid.com',
        'origin':'https://it.eurosportplayer.com',
        'x-bamsdk-version':'3.3',
        'authorization':'Bearer '+client_api_key,
        'content-type':'application/x-www-form-urlencoded',
        'x-bamsdk-platform':'linux',
        'accept':'application/json',
        'user-agent':user_agent,
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

    if debug:
        with open("step5.json", "w") as fileh:
            json.dump(rj, fileh, sort_keys = True, indent = 4, ensure_ascii = False)

    access_token = rj['access_token']
    refresh_token = rj['refresh_token']
    expires_in = rj['expires_in']

    return access_token, refresh_token, expires_in


def main(args):

    email = args.username
    esp_url = args.esp_url
    nprocesses = args.nprocesses

    try:
        password = args.password
    except AttributeError:
        print("You need to provide a password for the account")
        exit()

    if args.overwrite:
        assert(args.continuedown is False)
        if os.path.isdir("./download/stream"):
            shutil.rmtree("./download/stream")
        if os.path.isdir("./download/videos"):
            shutil.rmtree("./download/videos")

    if args.continuedown:
        assert(args.overwrite is False)
        os.makedirs("./download/stream", exist_ok=True)
        os.makedirs("./download/videos", exist_ok=True)
    else:
        os.makedirs("./download/stream", exist_ok=False)
        os.makedirs("./download/videos", exist_ok=False)

    #*********************************************************#
    # 1. Get clientApiKey
    #*********************************************************#
    print("*"*10+" STEP 1 "+"*"*10)
    clientApiKey = getClientApiKey()

    #*********************************************************#
    # 2. Get access_token
    #*********************************************************#
    print("*"*10+" STEP 2 "+"*"*10)
    access_token, refresh_token, expires_in = getAnonymAccessToken(client_api_key, user_agent)

    #*********************************************************#
    # 3. Login (get id_token)
    #*********************************************************#
    print("*"*10+" STEP 3 "+"*"*10)
    id_token = getAuthIdToken(access_token, user_agent, email, password)

    #*********************************************************#
    # 4. Login (get assertion)
    #*********************************************************#
    print("*"*10+" STEP 4 "+"*"*10)
    assertion = getAuthAssertion(access_token, user_agent, id_token)
    if verbose:
        print("assertion={}\n".format(assertion))

    #*********************************************************#
    # 5. Get access_token
    #*********************************************************#
    print("*"*10+" STEP 5 "+"*"*10)
    access_token, refresh_token, expires_in = getAuthAccessToken(client_api_key, user_agent)

    #*********************************************************#
    # 6. Get metadata and master file
    #*********************************************************#
    print("*"*10+" STEP 6 "+"*"*10)

    pos2 = esp_url.rfind("/")
    pos1 = esp_url.rfind("/",0,pos2-1)
    #print(pos2)
    #print(pos1)
    title = esp_url[pos1+1:pos2]
    contentID = esp_url[pos2+1:]

    if verbose:
        print("Title='"+title+"'")
        print("contentID='"+contentID+"'")

    metadata = getVideoMetadata(esp_url, access_token, title, contentID)
    master_url = getMasterFile(esp_url, metadata, access_token)

    if verbose:
        print("masterfile_url="+master_url)

    #*********************************************************#
    # 7. Download video frames
    #*********************************************************#

    print("*"*10+" STEP 7 "+"*"*10)

    # Download master file
    master_local = "./download/stream/master.m3u8"
    downloadFile(master_url, master_local)

    streams_dict = dict()
    master_file = None

    # Process master file
    with open(master_local, "r") as fileh:
        master_file = fileh.readlines()

    for linen, line in enumerate(master_file):
        if line.startswith("#EXT-X-STREAM-INF:RESOLUTION="):

            resolution = re.search('RESOLUTION=(.*),AVERAGE', line, re.IGNORECASE)
            if(resolution is None):
                print("ERROR: resolution is none")
                print(line)
                exit()
            resolution = resolution.group(1)

            stream_url = None
            url_search = re.search('URI="(.*)"', line, re.IGNORECASE)
            if url_search:
                stream_url = url_search.group(1)
            else:
                next_line = master_file[linen+1]
                if next_line[0] != "#":
                    stream_url = next_line.replace("\n","")
            assert(stream_url is not None)
            streams_dict[resolution] = stream_url

            # Download the stream playlist (for debug purposes)
            stream_url_full = master_url.replace("master_desktop_complete-trimmed.m3u8","") + stream_url
            stream_name = stream_url[stream_url.find("/")+1:]
            local_stream_file = "./download/stream/{}".format(stream_name)
            downloadFile(stream_url_full, local_stream_file)

    # Choose which stream to use
    playlist_url_rel = None

    # Ask the user
    if args.resolution=='c':
        stream_map = list()
        for i, (res, url) in enumerate(streams_dict.items()):
            print(str(i)+". "+ res + " - URL: "+url)
            stream_map.append(url)
        streamn = input("Choose the stream you want: ")
        streamn = int(streamn)
        playlist_url_rel = stream_map[streamn]

    # Use the command line argument to choose which stream (resolution) to use
    else:
        if args.resolution in streams_dict:
            playlist_url_rel = streams_dict[args.resolution]
        else:
            print("ERROR: The resolution you want is not available")

    # Save configuration in file (in order to quickly resume the download later and remember the paramenters, like the URL, in order to resume the download
    saveConfig(args)

    # Get stream playlist
    if debug:
        print("Remote playlist relative URL: "+playlist_url_rel)
    playlist_url = master_url.replace("master_desktop_complete-trimmed.m3u8","") + playlist_url_rel
    local_playlist_file = "./download/stream/frames.m3u8"
    if os.path.isfile(local_playlist_file):
        os.remove(local_playlist_file)
    downloadFile(playlist_url, local_playlist_file)

    # Base URL of the video fragments files
    frame_baseurl = master_url.replace("master_desktop_complete-trimmed.m3u8","") + playlist_url_rel[:playlist_url_rel.find("/")+1]
    if debug:
        print("frame_baseurl="+frame_baseurl)

    # Create file in which to write fragment list, to be used later by ffmpeg
    global list_fileh
    list_fileh = open("./download/fragments_list.txt", "a")

    frames_counter = Counter()
    # Process the frames playlist to download single video fragments
    frames_to_download = procPlaylist(esp_url, local_playlist_file, frame_baseurl, access_token, args, frames_counter)
    frames_count = len(frames_to_download) + frames_counter.val.value

    pool = mp.Pool(initializer=init_creator_pool, initargs=(frames_counter,frames_count,), processes=nprocesses)

    i = pool.map(downloadVideoFrame, frames_to_download)

    list_fileh.close()
    print("Video downloaded")

def saveConfig(args):
    del args.password
    frozen = jsonpickle.encode(args)
    frozen = json.dumps(json.loads(frozen), indent="\t", sort_keys=True)
    with open("last.json","w") as fileh:
        fileh.write(frozen)

#MAIN
if __name__=="__main__":

    parser = argparse.ArgumentParser(description='Download videos from eurosportplayer.com')
    parser.add_argument('--user', '-u', dest='username', help='Username (typically an e-mail address) of the eurosportplayer account')
    parser.add_argument('--password', '-p', dest='password', help='Password of the eurosportplayer account')
    parser.add_argument('--resolution', '-r', default='c', help='Resolution of the video to download')

    parser.add_argument('--nprocesses', type=int, help='Number of parallel processes to use', default=1)

    parser.add_argument('--verbose', help='Show more messages', action='store_true')

    load_group = parser.add_mutually_exclusive_group(required=True)
    load_group.add_argument('--load', action="store_true", help='Load from previous session')
    load_group.add_argument('--url', dest='esp_url', metavar='URL', help='URL of the video')

    continue_group = parser.add_mutually_exclusive_group(required=False)
    continue_group.add_argument('--continue', dest='continuedown', action='store_true', help='Continue the previous download')
    continue_group.add_argument('--overwrite', action='store_true', help='Delete the previous download')

    args = parser.parse_args()

    if (args.load):
        if(args.verbose):
            print("Reading configuration file")
        with open("last.json","r") as fileh:
            args2 = jsonpickle.decode(fileh.read())
        args2.continuedown = True
        args2.overwrite = False
        if(args.password is None):
            print("If you use the --load option, you still need to provide a password for the account using the --password option, since the password is not stored in the configuration file")
            exit()
        args2.password = args.password
        main(args2)

    else:
        main(args)

    exit()
