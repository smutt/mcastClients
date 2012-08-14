#!/usr/bin/env python
'''
Copyright (C) 2012 Andrew McConachie

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

import os
import time
import random
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp,srp1,IP,Ether,conf,UDP,BOOTP,DHCP
from scapy.contrib.igmp import IGMP

class STB:
  def __init__(self,m,g,t,s):
    self.ether = m
    self.group = g
    if(s):
      self.src = s
    else:
      self.src = doDhcp(self.ether)
    self.timeOut = t
    self.join()

  def refresh(self,g,t):
    self.leave()
    self.group = g
    self.timeOut = t
    self.join()
    
  def join(self):
    print "Joining " + self.group + " from " + self.src + " t=" + str(self.timeOut)
    l2 = Ether(dst=ipToMac(self.group,1), src=self.ether, type=0x800)
    l3 = IP(proto=2, ttl=1, src=self.src, dst=self.group)
    l4 = IGMP(gaddr=self.group, type=0x16)
    sendp(l2/l3/l4)

  def leave(self):
    print "Leaving " + self.group + " from " + self.src
    l2 = Ether(dst="01:00:5e:00:00:02", src=self.ether, type=0x800)
    l3 = IP(proto=2, ttl=1, src=self.src, dst="224.0.0.2")
    l4 = IGMP(gaddr=self.group, type=0x17)
    sendp(l2/l3/l4)

# Performs DHCP
def doDhcp(mac):
  chmac = macToChaddr(mac)

  L2 = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
  L3 = IP(src="0.0.0.0", dst="255.255.255.255")
  L4 = UDP(sport=68, dport=67)
  L5 = BOOTP(chaddr=chmac)
  L6 = DHCP(options=[("message-type","discover"),"end"])

  resp = srp1(L2/L3/L4/L5/L6, filter="udp and port 68", timeout=5)

  try:
    srcIP = resp.yiaddr
  except AttributeError:
    print "Failed to acquire IP via DHCP for " + mac
    sys.exit(1)

  for x in resp.lastlayer().options:
    if(x == 'end'):
      break
    op,val = x
    if(op == "subnet_mask"):
      subnet_mask = val
    elif(op == 'server_id'):
      server_id = val

  L5 = BOOTP(chaddr=chmac, yiaddr=srcIP)
  L6 = DHCP(options=[("message-type","request"), ("server_id",server_id), ("subnet_mask",subnet_mask), ("requested_addr",srcIP), "end"])
  sendp(L2/L3/L4/L5/L6)
  return srcIP

# Creates MAC from IP
def ipToMac(addy,mcast=0):
  if(mcast):
    mac = "01:00:5e"
  else:
    mac = "00:00:00"

  octets = addy.split(".")
  for x in range(1,4):
    num = str(hex(int(octets[x])))
    num =  num.split("x")[1]
    if len(num) < 2:
      num = "0" + str(num)
    mac += ":" + num
  return mac

# Increments an IP Address
def incIP(ip, n=1):
  if n < 1: return ip
  o = ip.split(".")
  for ii in range(3,-1,-1):
    if int(o[ii]) < 255:
      o[ii] = str(int(o[ii]) + 1)
      break
    else: 
      o[ii] = str(0)

  n -= 1
  return incIP(".".join(o),n)

# Increments a MAC address
def incMAC(mac):  
  if(isinstance(mac, str)):
    macAr = mac.split(":")
  else:
    macAr = mac

  x = macAr.pop()
  if(x != 'ff'):
    x = int(x, 16)
    x += 1
    x = hex(x)
    if(len(x) > 3):
      macAr.append(x[2] + x[3])
      return reduce(lambda x,y: x + ":" + y, macAr)
    else:
      macAr.append("0" + x[2])
      return reduce(lambda x,y: x + ":" + y, macAr)
  else:
    return incMac(macAr) + ':00'

# Converts str MAC to weird pcap DHCP chaddr format
def macToChaddr(mac):
  rv = []
  mac = mac.split(":")
  for x in mac:
    rv.append(chr(int(x, 16)))
  return reduce(lambda x,y: x + y, rv)

# Prints Usage
def usage():
  print "USAGE: mcastClients.py [ -i iface ] [ -c numClients ] [ -s IP ] [ -g group groupCount ] [ -t timeout ]"
  print " -i Use iface as egress interface for all packets(default:eth0)"
  print " -c Emulate numClients number of clients (default:10)"
  print " -s Use IP as starting source IPv4 address for clients(will default to DHCP if not specified)"
  print " -g Use group as starting IPMC group and groupCount as total number of IPMC groups(default:239.0.0.1 10)"
  print " -t Use timeout as maximum time a single IPMC group will be joined before leaving(default:20)"
  print "Note: Interface iface MUST be placed in promiscious mode manually.  Linux: ifconfig iface promisc"

# Parse args and overwrite defaults
def parseArgs(args):
  global dev, srcIP, numClients, firstGrp, grpCnt, maxTimeout, dhcp
  if len(args) < 2: return

  tmp = str(args.pop(1))
  if tmp == '-i': dev = str(args.pop(1))
  elif tmp == '-c':
    numClients = int(args.pop(1))
  elif tmp == '-s':
    srcIP = str(args.pop(1))
    dhcp = False
  elif tmp == '-g':
    firstGrp = str(args.pop(1))
    grpCnt = int(args.pop(1))
  elif tmp == '-t':
    maxTimeout = int(args.pop(1))
  else:
    usage()
    sys.exit(1)
  parseArgs(args)

###################
# BEGIN EXECUTION #
###################
# Defaults and initializations
dev = "eth0"
numClients = 10
firstMAC = "00:be:ef:00:00:01"
firstIP = "1.1.1.100"
firstGrp = "239.0.0.1"
grpCnt = 100
maxTimeout = 20
dhcp = True
clients = []
args = []
random.seed()

parseArgs(sys.argv) # Parse initial args
sys.setrecursionlimit(max(sys.getrecursionlimit(),grpCnt+1000)) # Necessary for incIP
conf.iface = dev # Set our default Scapy interface
conf.verb = 0 # Disable Scapy verbosity
conf.checkIPaddr = 0 # Don't check response packets for matching destination IPs

# Seed our STBs
print "Using " + dev
seedMAC = firstMAC
seedSrc = firstIP
seedGrp = firstGrp
ii = 1
for x in range(0,numClients):
  if(dhcp):
    clients.append(STB(seedMAC, seedGrp, random.randint(1,maxTimeout), False))
  else:
    clients.append(STB(seedMAC, seedGrp, random.randint(1,maxTimeout), seedSrc))
    seedSrc = incIP(seedSrc)
    
  seedMAC = incMAC(seedMAC)
  if ii < grpCnt:
    seedGrp = incIP(seedGrp)
    ii += 1
  else:
    seedGrp = firstGrp
    ii = 1
    
# Keep changing our channels until Ctrl-C
while len(clients) > 0:
    try:
      time.sleep(1)
      for c in clients:
        if c.timeOut == 0:
          c.refresh(incIP(firstGrp,random.randint(0,grpCnt)),random.randint(1,maxTimeout))
        else:
          c.timeOut -= 1
    except KeyboardInterrupt:
      print "Caught keyboard interrupt. Exiting."
      sys.exit(0)
