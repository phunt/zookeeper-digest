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

# more information from scapy
#import logging
#logging.getLogger("scapy").setLevel(logging.DEBUG)

from scapy.all import *

from optparse import OptionParser

usage = "usage: %prog [options]"
parser = OptionParser(usage=usage)
parser.add_option("", "--servers", dest="servers",
                  default="localhost:2181", help="comma separated list of host:port")

parser.add_option("-i", "--intf", dest="interface",
                  default=None, help="interface from which to read packets")
parser.add_option("-r", "--read", dest="read",
                  default=None, help="pcap file from which to read packets")

parser.add_option("", "--show",
                  action="store_true", dest="show", default=False,
                  help="show full packet detail")
parser.add_option("", "--summary",
                  action="store_true", dest="summary", default=False,
                  help="show summary packet detail")

parser.add_option("", "--debug",
                  action="store_true", dest="debug", default=False,
                  help="show all pkts")

(options, args) = parser.parse_args()

outstanding_reqs = {}
sessionids = {}

class ZKReq(Packet):
    fields_desc=[ SignedIntField("len", 0) ]

    def guess_payload_class(self, payload):
        if len(payload) >= 28:
            n = ZKConnectReq(_pkt=payload)
            if (n.protocolVersion == 0 and n.timeout >= 0 and n.len_passwd == 16):
                return ZKConnectReq

        return ZKReqType

    def mysummary(self):
        src = self.underlayer.underlayer.src
        sport = self.underlayer.sport
        return self.sprintf("ZKReq  < %s:%s" % (str(src), str(sport)))

bind_layers( TCP, ZKReq, dport=2181 )

class ZKResp(Packet):
    fields_desc=[ SignedIntField("len", 0) ]

    def guess_payload_class(self, payload):
        if len(payload) >= 20:
            n = ZKConnectResp(_pkt=payload)
            if (n.protocolVersion == 0 and n.timeout >= 0 and n.len_passwd == 16):
                return ZKConnectResp

        return ZKRespType

    def mysummary(self):
        dst = self.underlayer.underlayer.dst
        dport = self.underlayer.dport
        return self.sprintf("ZKResp > %s:%s" % (str(dst), str(dport)))

bind_layers( TCP, ZKResp, sport=2181 )

class ZKConnectReq(Packet):
    fields_desc=[ SignedIntField("protocolVersion", 0),
                  XLongField("lastZxidSeen", 0),
                  SignedIntField("timeout", 30000),
                  XLongField("sessionId", 0),
                  FieldLenField("len_passwd", None, fmt="I", length_of="passwd"),
                  StrLenField("passwd", "", length_from=lambda pkt:pkt.len_passwd) ]

    def mysummary(self):
        return self.sprintf("ZKConnectReq %ZKConnectReq.lastZxidSeen% %ZKConnectReq.timeout% %ZKConnectReq.sessionId%"),[ZKReq]

class ZKConnectResp(Packet):
    fields_desc=[ SignedIntField("protocolVersion", 0),
                  SignedIntField("timeout", 30000),
                  XLongField("sessionId", 0),
                  FieldLenField("len_passwd", None, fmt="I", length_of="passwd"),
                  StrLenField("passwd", "", length_from=lambda pkt:pkt.len_passwd) ]

    def mysummary(self):
        return self.sprintf("ZKConnectResp %ZKConnectResp.timeout% %ZKConnectResp.sessionId%"),[ZKResp]

class ZKReqType(Packet):
    fields_desc=[ SignedIntEnumField("xid", 0, {-1:"NOTIFICATION", -2:"PING", -4:"AUTH"}),
                  SignedIntEnumField("type", 0, {-11:"CLOSE",0:"EVENT",1:"CREATE",
                      2:"DELETE",3:"EXISTS",4:"GETDATA",5:"SETDATA",8:"GETCHILD",
                      11:"PING",12:"GETCHILD2"}) ]

    def mysummary(self):
        return self.sprintf("ZKReqType 0x%x,sessionId%L %ZKReqType.type%"),[ZKReq]

class ZKRespType(Packet):
    fields_desc=[ SignedIntEnumField("xid", 0, {-1:"NOTIFICATION", -2:"PING", -4:"AUTH"}),
                  XLongField("zxid", 0),
                  SignedIntField("err", 0) ]

    def guess_payload_class(self, payload):
        dst = self.underlayer.underlayer.underlayer.dst
        dport = self.underlayer.underlayer.dport
        req = outstanding_reqs.get((dst, dport, self.xid), None)
        if req:
            del outstanding_reqs[dst, dport, self.xid]
            self.type = req.sprintf("%ZKReqType.type%")
            return req.payload.reply_type()

    def mysummary(self):
        if not getattr(self, 'type', None):
            if self.xid == -2:
                self.type = "PING"
            else:
                dst = self.underlayer.underlayer.underlayer.dst
                dport = self.underlayer.underlayer.dport
                req = outstanding_reqs.get((dst, dport, self.xid), None)
                if req:
                    del outstanding_reqs[dst, dport, self.xid]
                    self.type = req.sprintf("%ZKReqType.type%")
        return self.sprintf("ZKRespType 0x%x,sessionId%L %ZKRespType.type%"),[ZKResp]

class GetDataReq(Packet):
    fields_desc=[ FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path),
                  ByteField("watch", 0) ]

    def reply_type(self):
        return GetDataResp

class SetDataReq(Packet):
    fields_desc=[ FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path),
                  FieldLenField("len_data", None, fmt="I", length_of="data"),
                  StrLenField("data", "", length_from=lambda pkt:pkt.len_data),
                  SignedIntField("version", 0) ]

    def reply_type(self):
        return SetDataResp

class ExistsReq(Packet):
    fields_desc=[ FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path),
                  ByteField("watch", 0) ]

    def reply_type(self):
        return ExistsResp

class Acl(Packet):
    fields_desc=[ SignedIntField("perms", 0),
                  StrLenField("scheme", "", length_from=lambda pkt:pkt.len_scheme),
                  FieldLenField("len_scheme", None, fmt="I", length_of="scheme"),
                  StrLenField("scheme", "", length_from=lambda pkt:pkt.len_scheme),
                  FieldLenField("len_id", None, fmt="I", length_of="id"),
                  StrLenField("id", "", length_from=lambda pkt:pkt.len_id) ]

    def extract_padding(self, pay):
        return "",pay

class CreateReq(Packet):
    fields_desc=[ FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path),
                  FieldLenField("len_data", None, fmt="I", length_of="data"),
                  StrLenField("data", "", length_from=lambda pkt:pkt.len_data),
                  FieldLenField("count_acls", None, fmt="I", count_of="acls"),
                  PacketListField("acls", None, Acl, count_from=lambda pkt:pkt.count_acls),
                  SignedIntField("flags", 0) ]

    def reply_type(self):
        return ExistsResp

class DeleteReq(Packet):
    fields_desc=[ FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path),
                  SignedIntField("version", 0) ]

    def reply_type(self):
        return DeleteResp

class GetChildrenReq(Packet):
    fields_desc=[ FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path),
                  ByteField("watch", 0) ]

    def reply_type(self):
        return GetChildrenResp

class GetChildren2Req(Packet):
    fields_desc=[ FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path),
                  ByteField("watch", 0) ]

    def reply_type(self):
        return GetChildren2Resp

class WatcherEvent(Packet):
    fields_desc=[ SignedIntField("type", 0),
                  SignedIntField("state", 0),
                  FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path) ]

bind_layers( ZKReqType, WatcherEvent, type=0 )
bind_layers( ZKReqType, CreateReq, type=1 )
bind_layers( ZKReqType, DeleteReq, type=2 )
bind_layers( ZKReqType, ExistsReq, type=3 )
bind_layers( ZKReqType, GetDataReq, type=4 )
bind_layers( ZKReqType, SetDataReq, type=5 )
bind_layers( ZKReqType, GetChildrenReq, type=8 )
bind_layers( ZKReqType, GetChildren2Req, type=12 )

class GetDataResp(Packet):
    fields_desc=[ FieldLenField("len_data", None, fmt="I", length_of="data"),
                  StrLenField("data", "", length_from=lambda pkt:pkt.len_data) ]

class SetDataResp(Packet):
    pass

class DeleteResp(Packet):
    pass

class Child(Packet):
    fields_desc=[ FieldLenField("len_name", None, fmt="I", length_of="name"),
                  StrLenField("name", "", length_from=lambda pkt:pkt.len_name) ]

    def extract_padding(self, pay):
        return "",pay

class GetChildrenResp(Packet):
    fields_desc=[ FieldLenField("count_children", None, fmt="I", count_of="children"),
                  PacketListField("children", None, Child,
                                  count_from=lambda pkt:pkt.count_children) ]

class GetChildren2Resp(GetChildrenResp):
    pass

class Stat(Packet):
    fields_desc=[ XLongField("czxid", 0),
                  XLongField("mzxid", 0),
                  LongField("ctime", 0),
                  LongField("mtime", 0),
                  SignedIntField("version", 0),
                  SignedIntField("cversion", 0),
                  SignedIntField("aversion", 0),
                  XLongField("ephemeralOwner", 0),
                  SignedIntField("dataLength", 0),
                  SignedIntField("numChildren", 0),
                  XLongField("pzxid", 0) ]

bind_layers( GetDataResp, Stat )
bind_layers( SetDataResp, Stat )
bind_layers( GetChildren2Resp, Stat )

def process_req(p):
    if options.debug:
        if options.summary: print(p.summary())
        elif options.show: print(p.show())

    
    if p.haslayer(ZKReqType):
        reqType = p.getlayer(ZKReqType)
        outstanding_reqs[p[IP].src,p[TCP].sport,reqType.xid] = reqType
        try:
            reqType.sessionId = sessionids[reqType.underlayer.underlayer.underlayer.src,
                                           reqType.underlayer.underlayer.sport]
        except:
            pass
    elif p.haslayer(ZKRespType):
        respType = p.getlayer(ZKRespType)
        try:
            respType.sessionId = sessionids[respType.underlayer.underlayer.underlayer.dst,
                                            respType.underlayer.underlayer.dport]
        except:
            pass
    elif p.haslayer(ZKConnectResp):
        cresp = p.getlayer(ZKConnectResp)
        sessionids[cresp.underlayer.underlayer.underlayer.dst,
                   cresp.underlayer.underlayer.dport] = cresp.sessionId

    if p.haslayer(ZKReq) or p.haslayer(ZKResp) or options.debug:
        if options.summary: print(p.summary())
        elif options.show: print(p.show())

if __name__ == '__main__':
    if options.read:
        pkts = rdpcap(options.read)
        for p in pkts:
            process_req(p)
    elif options.interface == 'lo':
        s=conf.L3socket(iface=options.interface)
        while 1:
            p=s.recv(MTU)
            if not p: continue

            if not p.sprintf("%TCP.sport%") == "2181" and not p.sprintf("%TCP.dport%") == "2181":
                continue

            process_req(p)
    elif options.interface:
        sniff(iface=options.interface, filter="tcp and ( port 2181 )",
              prn=lambda p: process_req(p))
