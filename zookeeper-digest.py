#!/usr/bin/env python

# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import re
import binascii
import socket

from optparse import OptionParser

usage = "usage: %prog [options]"
parser = OptionParser(usage=usage)
parser.add_option("", "--type", dest="type",
                  default="tcpdump", help="input type, currently only tcpdump is supported")
parser.add_option("", "--servers", dest="servers",
                  default="localhost:2181", help="comma separated list of host:port")
parser.add_option("", "--input", dest="input",
                  default=None, help="input file, default is stdin")

(options, args) = parser.parse_args()

class Packet(object):
    def __init__(self, datetime, src, dst, tcplen=0):
        self.datetime = datetime
        self.src = src
        self.dst = dst
        self.hdr = []
        self.data = []
        self.tcplen = tcplen

    def prep(self):
        if self.hdr: return
        self.hdr = []
        for d in self.data:
            dlen = len(d)
            if dlen == 4:
                self.hdr.append(d[:2])
                self.hdr.append(d[2:4])
            elif dlen == 2:
                self.hdr.append(d)
        if self.tcplen > 0:
            self.data = self.hdr[-tcplen:]
            self.data_snap = self.hdr[-tcplen:]
            self.hdr = self.hdr[:len(self.hdr)-tcplen]

    def rollback_data(self):
        self.data = self.data_snap
        self.zklen = self.read32()

OP_NOTIFICATION = 0
OP_CREATE = 1
OP_DELETE = 2
OP_EXISTS = 3
OP_GETDATA = 4
OP_SETDATA = 5
OP_GETACL = 6
OP_SETACL = 7
OP_GETCHILDREN = 8
OP_SYNC = 9
OP_PING = 11
OP_AUTH = 100
OP_SETWATCHES = 101
OP_CREATESESSION = -10
OP_CLOSESESSION = -11
OP_ERROR = -1

valid_ops = [OP_NOTIFICATION, OP_CREATE, OP_DELETE, OP_EXISTS, OP_GETDATA,
             OP_SETDATA, OP_GETACL, OP_SETACL, OP_GETCHILDREN, OP_SYNC,
             OP_PING, OP_AUTH, OP_SETWATCHES, OP_CREATESESSION, OP_CLOSESESSION,
             OP_ERROR]

EOK = 0
ESYSTEMERROR = -1
ERUNTIMEINCONSISTENCY = -2
EDATAINCONSISTENCY = -3
ECONNECTIONLOSS = -4
EMARSHALLINGERROR = -5
EUNIMPLEMENTED = -6
EOPERATIONTIMEOUT = -7
EBADARGUMENTS = -8
EAPIERROR = -100
ENONODE = -101
ENOAUTH = -102
EBADVERSION = -103
ENOCHILDRENFOREPHEMERALS = -108
ENODEEXISTS = -110
ENOTEMPTY = -111
ESESSIONEXPIRED = -112
EINVALIDCALLBACK = -113
EINVALIDACL = -114
EAUTHFAILED = -115
ESESSIONMOVED = -118

valid_errs = [EOK, ESYSTEMERROR, ERUNTIMEINCONSISTENCY, EDATAINCONSISTENCY,
              ECONNECTIONLOSS, EMARSHALLINGERROR, EUNIMPLEMENTED,
              EOPERATIONTIMEOUT, EBADARGUMENTS, EAPIERROR, ENONODE, ENOAUTH,
              EBADVERSION, ENOCHILDRENFOREPHEMERALS, ENODEEXISTS, ENOTEMPTY,
              ESESSIONEXPIRED, EINVALIDCALLBACK, EINVALIDACL, EAUTHFAILED,
              ESESSIONMOVED]

class Op(object):
    pass

class OpRequest(Op):
    pass

class OpResponse(Op):
    pass

class PingRequest(OpRequest):
    def __init__(self, p):
        pass

    @staticmethod
    def parse(p):
        print("parsing PingRequest")
        result = PingRequest(p)
        def a(p): print("PingResponse"); return PingResponse(p)
        addreq(p.src, p.xid, a)
        return result

    def deb(self):
        return "PingRequest"

class PingResponse(OpResponse):
    def __init__(self, p):
        pass

    @staticmethod
    def parse(p):
        print("parsing PingResponse")
        return PingResponse(p)

    def deb(self):
        return "PingResponse"

class CloseSessionRequest(OpRequest):
    def __init__(self, p):
        pass

    @staticmethod
    def parse(p):
        print("parsing CloseSessionRequest")
        return CloseSessionRequest(p)

    def deb(self):
        return "CloseSessionRequest"

class ConnectRequest(OpRequest):
    def __init__(self, p):
        self.protocol_version = p.read32()
        self.last_zxid_seen = p.read64()
        self.time_out = p.read32()
        self.session_id = p.read64()
        plen = p.read32()
        self.passwd = p.readbin(plen)

    @staticmethod
    def parse(p):
        print("parsing ConnectRequest")
        if p.peek32(0) == 0 and p.peek32(24) == p.zklen - 28:
            return ConnectRequest(p)

    def deb(self):
        return "ConnectRequest"

class ConnectResponse(OpResponse):
    def __init__(self, p):
        self.protocol_version = p.read32()
        self.time_out = p.read32()
        self.session_id = p.read64()
        plen = p.read32()
        self.passwd = p.readbin(plen)

    @staticmethod
    def parse(p):
        print("parsing ConnectResponse")
        if p.peek32(0) == 0 and p.peek32(16) == p.zklen - 20:
            return ConnectResponse(p)

    def deb(self):
        return "ConnectResponse"

class SetWatchesRequest(OpRequest):
    def __init__(self, p):
        self.relative_zxid = p.read64()
        data_watches = p.read32()
        self.data_watches = []
        for i in xrange(data_watches):
            wlen = p.read32()
            self.data_watches.append(p.readstr(wlen))
        exist_watches = p.read32()
        self.exist_watches = []
        for i in xrange(exist_watches):
            wlen = p.read32()
            self.exist_watches.append(p.readstr(wlen))
        child_watches = p.read32()
        self.child_watches = []
        for i in xrange(child_watches):
            wlen = p.read32()
            self.child_watches.append(p.readstr(wlen))

    @staticmethod
    def parse(p):
        print("parsing SetWatchesRequest")
        off = 8
        data_watches = p.peek32(off)
        off += 4
        for i in xrange(data_watches):
            off += p.peek32(off) + 4
        exist_watches = p.peek32(off)
        off += 4
        for i in xrange(exist_watches):
            off += p.peek32(off) + 4
        child_watches = p.peek32(off)
        off += 4
        for i in xrange(child_watches):
            off += p.peek32(off) + 4

        result = SetWatchesRequest(p)
        def a(p): print("SetWatchesResponse"); return SetWatchesResponse(p)
        addreq(p.src, p.xid, a)
        return result

    def deb(self):
        return "SetWatchesRequest"

class SetWatchesResponse(OpResponse):
    def __init__(self, p):
        pass

    @staticmethod
    def parse(p):
        print("parsing SetWatchesResponse")
        return SetWatchesResponse(p)

    def deb(self):
        return "SetWatchesResponse"

class Acl(object):
    def __init__(self, p):
        self.perms = p.read32()
        self.scheme = p.readstr(p.read32())
        self.id = p.readstr(p.read32())

class CreateRequest(OpRequest):
    def __init__(self, p):
        plen = p.read32()
        self.path = p.readstr(plen)
        dlen = p.read32()
        self.data = p.readbin(dlen)
        acnt = p.read32()
        self.acls = []
        for i in xrange(acnt):
            self.acls.append(Acl(p))
        self.flags = p.read32()

    @staticmethod
    def parse(p):
        print("parsing CreateRequest")
        plen = p.peek32(0)
        dlen = p.peek32(plen + 4)
        acnt = p.peek32(plen + dlen + 8)
        alen = 0
        base = plen + dlen + 12
        for i in xrange(acnt):
            slen = p.peek32(base + 4)
            ilen = p.peek32(base + slen + 8)
            alen += slen + ilen + 12
            base += alen

        if not plen + dlen + alen + 16 == p.zklen - 8:
            return None

        result = CreateRequest(p)
        def a(p): print("CreateResponse"); return CreateResponse(p)
        addreq(p.src, p.xid, a)
        return result

    def deb(self):
        return "CreateRequest"

class CreateResponse(OpResponse):
    def __init__(self, p):
        pass

    @staticmethod
    def parse(p):
        print("parsing CreateResponse")
        return CreateResponse(p)

    def deb(self):
        return "CreateResponse"

class GetDataRequest(OpRequest):
    def __init__(self, p):
        plen = p.read32()
        self.path = p.readstr(plen)
        self.watch = p.read8()

    @staticmethod
    def parse(p):
        print("parsing GetDataRequest")
        if not p.peek32(0) == p.zklen - 13 or not p.peek8(p.zklen - 9) in [0, 1]:
            return None
        result = GetDataRequest(p)
        def a(p): print("GetDataResponse"); return GetDataResponse(p)
        addreq(p.src, p.xid, a)
        return result

    def deb(self):
        return "GetDataRequest"

class Stat(object):
    def __init__(self, p):
        self.czxid = p.read64()
        self.mzxid = p.read64()
        self.ctime = p.read64()
        self.mtime = p.read64()
        self.version = p.read32()
        self.cversion = p.read32()
        self.aversion = p.read32()
        self.ephemeral_owner = p.read64()
        self.data_length = p.read32()
        self.num_children = p.read32()
        self.pzxid = p.read64()

class GetDataResponse(OpResponse):
    def __init__(self, p):
        dlen = p.read32()
        self.data = p.readbin(dlen)
        self.stat = Stat(p)

    @staticmethod
    def parse(p):
        print("parsing GetDataResponse")
        return GetDataResponse(p)

    def deb(self):
        return "GetDataResponse"

class SetDataRequest(OpRequest):
    def __init__(self, p):
        plen = p.read32()
        self.path = p.readstr(plen)
        dlen = p.read32()
        self.data = p.readbin(dlen)
        self.version = p.read32()

    @staticmethod
    def parse(p):
        print("parsing SetDataRequest")
        plen = p.peek32(0)
        dlen = p.peek32(plen + 4)
        if not plen + dlen + 12 == p.zklen - 8:
            return None

        result = SetDataRequest(p)
        def a(p): print("SetDataResponse"); return SetDataResponse(p)
        addreq(p.src, p.xid, a)
        return result

    def deb(self):
        return "SetDataRequest"

class SetDataResponse(OpResponse):
    def __init__(self, p):
        self.stat = Stat(p)

    @staticmethod
    def parse(p):
        print("parsing SetDataResponse")
        return SetDataResponse(p)

    def deb(self):
        return "SetDataResponse"

class ZKPacket(Packet):
    def __init__(self, datetime, src, dst, tcplen):
        Packet.__init__(self, datetime, src, dst, tcplen)

    def prep(self):
        Packet.prep(self)
        self.zklen = self.read32()
        print("zklen %d" % (self.zklen))

    def read64(self):
        int64 = long("".join(self.data[:8]), 16)
        if int64 > sys.maxint<<32 |0xffffffff:
            int64 = int64 - (2L * (sys.maxint<<32 |0xffffffff)) - 2
        self.data = self.data[8:]
        print("int64 %d" % (int64))
        return int64

    def read32(self):
        int32 = long("".join(self.data[:4]), 16)
        if int32 > sys.maxint:
            int32 = int32 - (2L * sys.maxint) - 2
        print("int32 %d" % (int32))
        self.data = self.data[4:]
        return int32

    def read16(self):
        int16 = int("".join(self.data[:2]), 16)
        print("int16 %d" % (int16))
        self.data = self.data[2:]
        return int16

    def read8(self):
        int8 = int("".join(self.data[:1]), 16)
        print("int8 %d" % (int8))
        self.data = self.data[1:]
        return int8

    def peek32(self, offset):
        int32 = int("".join(self.data[offset:offset+4]), 16)
        print("peek int32 %d" % (int32))
        return int32

    def peek8(self, offset):
        int8 = int("".join(self.data[offset:offset+1]), 16)
        print("peek int8 %d" % (int8))
        return int8

    def readbin(self, length):
        result = int("".join(self.data[:length]), 16)
        print("bin 0x%x" % (result))
        self.data = self.data[length:]
        return result

    def readstr(self, length):
        result = binascii.unhexlify("".join(self.data[:length]))
        print("str %s" % (result))
        self.data = self.data[length:]
        return result

    # server list
    # track cluster information - zxid
    # track session information, in particular state and xid

    def determine_type(self):
        self.request = False

        if self.zklen == 4:
            self.flw = True
            return
        else:
            self.flw = False

        if self.zklen == 8:
            self.xid = self.read32()
            self.type = self.read32()
            if self.type == OP_CLOSESESSION:
                self.op = CloseSessionRequest.parse(self)
                if self.op: return
            elif self.xid == -2 and self.type == OP_PING:
                self.op = PingRequest.parse(self)
                if self.op: return
            self.rollback_data()

        self.op = ConnectRequest.parse(self)
        if self.op: return

        self.op = ConnectResponse.parse(self)
        if self.op: return

        global valid_errs

        xid = self.peek32(0)
        if peekresp(self.dst, xid): #known response?
            print("parsing possible known response")
            self.xid = self.read32()
            self.zxid = self.read64()
            self.err = self.read32()
            if self.err in valid_errs:
                self.op = getresp(self.dst, self.xid, self)
                if self.op: return

            self.rollback_data()

        global valid_ops
        print("checking request")
        if self.peek32(4) in valid_ops: #request
            self.xid = self.read32()
            self.type = self.read32()
            if self.type == OP_NOTIFICATION:
                return
            elif self.type == OP_CREATE:
                self.op = CreateRequest.parse(self)
            elif self.type == OP_DELETE:
                return
            elif self.type == OP_EXISTS:
                return
            elif self.type == OP_GETDATA:
                self.op = GetDataRequest.parse(self)
            elif self.type == OP_SETDATA:
                self.op = SetDataRequest.parse(self)
            elif self.type == OP_GETACL:
                return
            elif self.type == OP_SETACL:
                return
            elif self.type == OP_GETCHILDREN:
                return
            elif self.type == OP_SYNC:
                return
            elif self.type == -2: # ping
                return
            elif self.type == OP_AUTH:
                return
            elif self.type == OP_SETWATCHES:
                self.op = SetWatchesRequest.parse(self)

            if self.op:
                return

        #response
        self.rollback_data()
        print("parsing response")
        self.xid = self.read32()
        self.zxid = self.read64()
        self.err = self.read32()
        if not self.err in valid_errs:
            return
        self.op = getresp(self.dst, self.xid, self)

    def deb(self):
        return self.op.deb()

def addreq(src, xid, handler):
    print("addreq %s %d" % (src, xid))
    sess = sessions_by_addr.get(src, None)
    if not sess:
        sess = Session()
        sessions_by_addr[src] = sess
    sess.addxid(xid, handler)

def getresp(addr, xid, p):
    print("getresp %s %d" % (addr, xid))
    sess = sessions_by_addr.get(addr)
    if not sess: return None
    req_xid, func = sess.popxid()
    if not func: return None
    if not req_xid == xid:
        print("xid %d != %d" % (req_xid, xid))
    return func(p)

def peekresp(addr, xid):
    print("peekresp %s %d" % (addr, xid))
    sess = sessions_by_addr.get(addr)
    if not sess: return False
    return xid == sess.peekxid()

class Session(object):
    def __init__(self):
        self.xids_pending = []

    def addxid(self, xid, response):
        self.xids_pending.append((xid, response))

    def popxid(self):
        return self.xids_pending.pop(0)

    def peekxid(self):
        if len(self.xids_pending):
            print("peekxid %d" % (self.xids_pending[0][0]))
            return self.xids_pending[0][0]
        return -1000

sessions_by_addr = {}        

S_UNKNOWN = -1
S_STARTING = 0
S_CONNECTING = 1
S_CONNECTED = 2
S_EXPIRED = 3
S_CLOSED = 4

def process(p):
    if not p: return
    if p.tcplen == 0: return
    try:
        p.prep()
        p.determine_type()
        print("determined type: %s" % (p.deb()))
    except Exception as e:
        print("unable to process frame %s" % (str(e)))

if __name__ == '__main__':
    header_re = re.compile(r"(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) IP (\d+\.\d+.\d+.\d+\.\d+) > (\d+\.\d+.\d+.\d+\.\d+): tcp (\d+)\s*", re.I)
    data_re = re.compile(r"\s+0x(\w{4}):\s+(.+)", re.I)

    p = None
    source = (options.input and open(options.input, 'r')) or sys.stdin
    try:
        for line in source:
            m = header_re.match(line)
            if m:
                process(p)

                datetime, src, dst, tcplen = m.groups()
                tcplen = int(tcplen)
                if tcplen > 0:
                    p = ZKPacket(datetime, src, dst, tcplen)
                else:
                    p = Packet(datetime, src, dst)
                continue

            m = data_re.match(line)
            if m:
                p.data.extend(m.group(2).strip().split(" "))
                continue

            print("Unknown input: " + line)
        process(p)
    finally:
        if options.input:
            source.close()
