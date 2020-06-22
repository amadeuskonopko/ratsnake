#!/usr/bin/python3
import struct

class adbCommand():

    def __init__(self, command, arg0, arg1=0, payload=""):
        self.command = command.encode('UTF-8')
        self.arg0 = struct.pack('<L', arg0)
        self.arg1 = struct.pack('<L', arg1)
        self.payload = payload.encode('UTF-8')
        self.magic = self.calc_magic()
        self.datalen = self.calc_datalen()
        self.crc32 = self.calc_crc32()
        self.adbPacket = self.adbPayload()

    def calc_magic(self):
        return struct.pack('<L', int.from_bytes(self.command, 'little') ^ 0xffffffff)

    def calc_datalen(self):
        return struct.pack('<L', len(self.payload))

    def calc_crc32(self):
        crc32 = 0
        for i in self.payload:
            crc32 += i
        return struct.pack('<L', crc32)

    def adbPayload(self):
        return self.command + self.arg0 + self.arg1 + self.datalen + self.crc32 + self.magic + self.payload

class adbExtract():

    def __init__(self, adbPacket):
        self.adbPacket = adbPacket
        self.adbMessages = self.extractCmds()
    
    def extractCmds(self):
        
        adbMessages = []
        adbMsg = {}
        adb_msg_len = 0

        while len(self.adbPacket) > 0:
            adbMsg["command"] = self.adbPacket[0:4]
            adbMsg["arg0"] = self.adbPacket[4:8]
            adbMsg["arg1"] = self.adbPacket[8:12]
            adbMsg["data_len"] = self.adbPacket[12:16]
            adbMsg["data_crc32"] = self.adbPacket[16:20]
            adbMsg["data_magic"] = self.adbPacket[20:24]
            adbMsg["payload"] = self.adbPacket[24:24+int.from_bytes(adbMsg["data_len"], 'little')]

            for key,val in adbMsg.items():
                adb_msg_len += len(val)

            # shift the payload 
            self.adbPacket = self.adbPacket[adb_msg_len:]

            # add the adb message to the list
            adbMessages.append(adbMsg)
            adb_msg_len = 0
            adbMsg = {}
        
        return adbMessages

# craft adb packet
#adbCommand("CNXN", 16777217, 256*4096, "host::features=abb_exec,fixed_push_symlink_timestamp,abb,stat_v2,apex,shell_v2,fixed_push_mkdir,cmd")

# test.adbPacket
#test = adbExtract(b'CNXN\x01\x00\x00\x01\x00\x00\x10\x00c\x00\x00\x00\x81&\x00\x00\xbc\xb1\xa7\xb1host::features=abb_exec,fixed_push_symlink_timestamp,abb,stat_v2,apex,shell_v2,fixed_push_mkdir,cmd')
#test.adbMessages
