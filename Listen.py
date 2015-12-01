#!/usr/bin/python
# -*- coding:utf-8 -*-
#author:iuyyoy

from ctypes import *
from winpcapy import *
import time
import sys
import string
import platform

class Listen(object):
    network_interface = []
    def __init__(self):
        self.LINE_LEN=16
        self.fp=pcap_t
        self.alldevs=POINTER(pcap_if_t)()
        self.d=POINTER(pcap_if_t)
        self.errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)
        self.header=POINTER(pcap_pkthdr)()
        self.pkt_data=POINTER(c_ubyte)()

    #获取网卡接口信息
    #Get network cards' interfaces
    def get_interfaces(self):
        ## Retrieve the device list
        if (pcap_findalldevs(byref(self.alldevs), self.errbuf) == -1):
            print self.errbuf.value
            return (False,"Error: No interfaces found!")
        ## Print the list
        self.num=0
        try:
            d=self.alldevs.contents
        except:
            print self.errbuf.value
            return (False,"Error: No interfaces found!\nMaybe you need admin privilege?")
        while d:
            self.num=self.num+1
            #print("%d. %s" % (self.num, d.name))
            if (d.description):
                self.network_interface.append((self.num,d.name,d.description))
                #print (" (%s)\n" % (d.description))
            else:
                self.network_interface.append((self.num,d.name,"(No description available)"))
                #print (" (No description available)\n")
            if d.next:
                d=d.next.contents
            else:
                d=False
        if (self.num==0):
            return (False,"Error: No interfaces found!\nMake sure WinPcap is installed.")
        return (True,"Success: Find %d network interfaces." %(self.num))

    #Show network cards' interfaces
    def print_network_interfaces(self):
    	for interface in self.network_interface:
        	print interface
        return 

    #Select adapter
    def select_adapter(self,inum):
        if inum in string.digits:
            inum=int(inum)
        else:
            inum=0
        if ((inum < 1) | (inum > self.num)):
            ## Free the device list
            pcap_freealldevs(self.alldevs)
            return (False,"Error: Interface number out of range.")
        d=self.alldevs
        for self.num in range(0,inum-1):
            d=d.contents.next
        self.fp = pcap_open_live(d.contents.name,65536,1,1000,self.errbuf)
        if (self.fp == None):
            pcap_freealldevs(self.alldevs)
            return (False,"Error: Can't opening adapter.")
        return (True,"Open adapter successfully.")

    #Read the packets
    def read_packets(self):
        res = pcap_next_ex(self.fp, byref(self.header), byref(self.pkt_data))
        while(res >= 0):
            if(res == 0):
                ## Timeout elapsed
                break
            
            """
			Add what you want to deal with the packets here.
            """
            rs = ''.join(chr(x) for x in self.pkt_data[0:self.header.contents.len])
            print rs
            res = pcap_next_ex(self.fp, byref(self.header), byref(self.pkt_data))

        if(res == -1):     
            return (False,"Error reading the packets: %s\n" % pcap_geterr(self.fp))
        return (True,"Finish reading packets.")
        
if __name__ == '__main__':
    sn =Listen()
    sn.get_interfaces()
    sn.print_network_interfaces()
    inum= raw_input('--> ')
    sn.select_adapter(inum)
    sn.read_packets()

    