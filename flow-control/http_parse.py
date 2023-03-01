#!/usr/bin/python
#
#Bertrone Matteo - Polytechnic of Turin
#November 2015
#
#eBPF application that parses HTTP packets
#and extracts (and prints on screen) the URL contained in the GET/POST request.
#
#eBPF program http_filter is used as SOCKET_FILTER attached to eth0 interface.
#only packet of type ip and tcp containing HTTP GET/POST are returned to userspace, others dropped
#
#python script uses bcc BPF Compiler Collection by iovisor (https://github.com/iovisor/bcc)
#and prints on stdout the first line of the HTTP GET/POST request containing the url

from __future__ import print_function
import time
from bcc import BPF
from sys import argv
import ctypes as ct

import pyroute2

MAX_STR_LEN = 2048
MAX_PATH_LEN = 64

class LongStr(ct.Structure):
    _fields_ = [("inner_str", ct.c_char * MAX_STR_LEN), ("index", ct.c_int), ("align", ct.c_int)]
class PathRule(ct.Structure):
    _fields_ = [("path_str", ct.c_char * MAX_PATH_LEN), ("length", ct.c_int), ("qps", ct.c_int)]
class PathRuleKey(ct.Structure):
    _fields_ = [("path_str", ct.c_char * MAX_PATH_LEN)]


ipr = pyroute2.IPRoute()
ipdb = pyroute2.IPDB(nl=ipr)
ifc = ipdb.interfaces.eth0

try:
    bpf = BPF(src_file = "http_parse.c",debug = 0)
    print("allocate memory for ebpf strings")
    counts = bpf.get_table("string_arr")
    counts[0] = LongStr(bytes(MAX_STR_LEN), 0, 0)
    path_rules = bpf.get_table("path_rules")

    path_rules[PathRuleKey(bytes("/", encoding="utf-8"))] = PathRule(bytes("/" + (MAX_PATH_LEN - 1) * ' ', encoding="utf-8"), 1, 0)
    path_rules[PathRuleKey(bytes("/aa", encoding="utf-8"))] = PathRule(bytes("/" + (MAX_PATH_LEN - 1) * ' ', encoding="utf-8"), 1, 0)

    print("allocate memory for ebpf string pool finish!")

    http_func = bpf.load_func("http_filter", BPF.SCHED_CLS)

    #ipr.tc("add", "clsact", ifc.index)
    ipr.tc("add", "ingress", ifc.index)
    ipr.tc("add-filter", "bpf", ifc.index, ":1", fd=http_func.fd, name=http_func.name, parent="ffff:fff3", classid=1, direct_action=True)
    try:
        while True:
            bpf.trace_print()
    except KeyboardInterrupt:
        pass
finally:
    #ipr.tc("del-filter", 'clsact', ifc.index, 'ffff:fff3')
    ipr.tc("del", "ingress", ifc.index)
    #ipr.tc("del", "clsact", ifc.index)
    #ipr.tc("del-filter", 'ingress', ifc.index)
