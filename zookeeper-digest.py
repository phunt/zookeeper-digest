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

(options, args) = parser.parse_args()

outstanding_reqs = {}

class ZooKeeperRequest(Packet):
    fields_desc=[ SignedIntField("len", 0) ]

    def guess_payload_class(self, payload):
        if len(payload) >= 28:
            n = ConnectRequest(_pkt=payload)
            if (n.protocolVersion == 0 and n.timeout >= 0 and n.len_passwd == 16):
                return ConnectRequest

        return ZooKeeperRequestType

bind_layers( TCP, ZooKeeperRequest, dport=2181 )

class ZooKeeperResponse(Packet):
    fields_desc=[ SignedIntField("len", 0) ]

    def guess_payload_class(self, payload):
        if len(payload) >= 20:
            n = ConnectResponse(_pkt=payload)
            if (n.protocolVersion == 0 and n.timeout >= 0 and n.len_passwd == 16):
                return ConnectResponse

        return ZooKeeperReplyType

bind_layers( TCP, ZooKeeperResponse, sport=2181 )

class ConnectRequest(Packet):
    fields_desc=[ SignedIntField("protocolVersion", 0),
                  XLongField("lastZxidSeen", 0),
                  SignedIntField("timeout", 30000),
                  XLongField("sessionId", 0),
                  FieldLenField("len_passwd", None, fmt="I", length_of="passwd"),
                  StrLenField("passwd", "", length_from=lambda pkt:pkt.len_passwd) ]

class ConnectResponse(Packet):
    fields_desc=[ SignedIntField("protocolVersion", 0),
                  SignedIntField("timeout", 30000),
                  XLongField("sessionId", 0),
                  FieldLenField("len_passwd", None, fmt="I", length_of="passwd"),
                  StrLenField("passwd", "", length_from=lambda pkt:pkt.len_passwd) ]

class ZooKeeperRequestType(Packet):
    fields_desc=[ SignedIntEnumField("xid", 0, {-1:"NOTIFICATION", -2:"PING", -4:"AUTH"}),
                  SignedIntField("type", 0) ]

class ZooKeeperReplyType(Packet):
    fields_desc=[ SignedIntEnumField("xid", 0, {-1:"NOTIFICATION", -2:"PING", -4:"AUTH"}),
                  XLongField("zxid", 0),
                  SignedIntField("err", 0) ]

    def guess_payload_class(self, payload):
        req = outstanding_reqs.get(self.xid, None)
        if req:
            return req.payload.reply_type() 

class GetDataRequest(Packet):
    fields_desc=[ FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path),
                  ByteField("watch", 0) ]

    def reply_type(self):
        return GetDataResponse

class SetDataRequest(Packet):
    fields_desc=[ FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path),
                  FieldLenField("len_data", None, fmt="I", length_of="data"),
                  StrLenField("data", "", length_from=lambda pkt:pkt.len_data),
                  SignedIntField("version", 0) ]

    def reply_type(self):
        return SetDataResponse

class ExistsRequest(Packet):
    fields_desc=[ FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path),
                  ByteField("watch", 0) ]

    def reply_type(self):
        return ExistsResponse

class Acl(Packet):
    fields_desc=[ SignedIntField("perms", 0),
                  StrLenField("scheme", "", length_from=lambda pkt:pkt.len_scheme),
                  FieldLenField("len_scheme", None, fmt="I", length_of="scheme"),
                  StrLenField("scheme", "", length_from=lambda pkt:pkt.len_scheme),
                  FieldLenField("len_id", None, fmt="I", length_of="id"),
                  StrLenField("id", "", length_from=lambda pkt:pkt.len_id) ]

    def extract_padding(self, pay):
        return "",pay

class CreateRequest(Packet):
    fields_desc=[ FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path),
                  FieldLenField("len_data", None, fmt="I", length_of="data"),
                  StrLenField("data", "", length_from=lambda pkt:pkt.len_data),
                  FieldLenField("count_acls", None, fmt="I", count_of="acls"),
                  PacketListField("acls", None, Acl, count_from=lambda pkt:pkt.count_acls),
                  SignedIntField("flags", 0) ]

    def reply_type(self):
        return ExistsResponse

class DeleteRequest(Packet):
    fields_desc=[ FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path),
                  SignedIntField("version", 0) ]

    def reply_type(self):
        return DeleteResponse

class GetChildrenRequest(Packet):
    fields_desc=[ FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path),
                  ByteField("watch", 0) ]

    def reply_type(self):
        return GetChildrenResponse

class GetChildren2Request(Packet):
    fields_desc=[ FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path),
                  ByteField("watch", 0) ]

    def reply_type(self):
        return GetChildren2Response

class WatcherEvent(Packet):
    fields_desc=[ SignedIntField("type", 0),
                  SignedIntField("state", 0),
                  FieldLenField("len_path", None, fmt="I", length_of="path"),
                  StrLenField("path", "", length_from=lambda pkt:pkt.len_path) ]

bind_layers( ZooKeeperRequestType, WatcherEvent, type=0 )
bind_layers( ZooKeeperRequestType, CreateRequest, type=1 )
bind_layers( ZooKeeperRequestType, DeleteRequest, type=2 )
bind_layers( ZooKeeperRequestType, ExistsRequest, type=3 )
bind_layers( ZooKeeperRequestType, GetDataRequest, type=4 )
bind_layers( ZooKeeperRequestType, SetDataRequest, type=5 )
bind_layers( ZooKeeperRequestType, GetChildrenRequest, type=8 )
bind_layers( ZooKeeperRequestType, GetChildren2Request, type=12 )

class GetDataResponse(Packet):
    fields_desc=[ FieldLenField("len_data", None, fmt="I", length_of="data"),
                  StrLenField("data", "", length_from=lambda pkt:pkt.len_data) ]

class SetDataResponse(Packet):
    pass

class DeleteResponse(Packet):
    pass

class Child(Packet):
    fields_desc=[ FieldLenField("len_name", None, fmt="I", length_of="name"),
                  StrLenField("name", "", length_from=lambda pkt:pkt.len_name) ]

    def extract_padding(self, pay):
        return "",pay

class GetChildrenResponse(Packet):
    fields_desc=[ FieldLenField("count_children", None, fmt="I", count_of="children"),
                  PacketListField("children", None, Child,
                                  count_from=lambda pkt:pkt.count_children) ]

class GetChildren2Response(GetChildrenResponse):
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

bind_layers( GetDataResponse, Stat )
bind_layers( SetDataResponse, Stat )
bind_layers( GetChildren2Response, Stat )

if __name__ == '__main__':
    if options.read:
        pkts = rdpcap(options.read)
    elif options.interface == 'lo':
        s=conf.L3socket(iface=options.interface, filter="tcp and ( port 2181 )")
        while 1:
            p=s.recv(MTU)
            if p:
                req = p[ZooKeeperRequestType]
                if req:
                    outstanding_reqs[req.xid] = req
                if options.summary: print(p.summary())
                elif options.show: print(p.show())
    elif options.interface:
        sniff(iface=options.interface, filter="tcp and ( port 2181 )",
              prn=lambda p: p.summary())
