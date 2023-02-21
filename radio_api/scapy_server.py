from scapy.all import *
import time
import struct
import pickle
from csv import writer
import sys

delays = []
csv_handler = open("packets.csv", 'a')

def custom_action(p):
    payload = bytearray(p.load)
    #print(payload)

    coloNodeID = payload[9]
    t = struct.unpack('d', payload[0:8])[0]

    delays.append([coloNodeID, time.time()-t, time.time()])
    w = writer(csv_handler)
    w.writerow(delays[-1])
    return #f"{coloNodeID} {time.time() - t}"

iface = sys.argv[1]
ports = " or ".join(sys.argv[2:])
print(ports)
sniff(filter=f"udp port {ports}", iface=iface, prn=custom_action)