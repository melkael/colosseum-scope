from scapy.all import *
import struct
import time
import sys

def convertScapyTimeToFloat(a):
    return float(repr(a)[9:-2])

def replay_pcap_udp(pcap, sending_interface, ip_dest, port_dest, coloNodeID):
    packets = sniff(offline=pcap, filter = "udp")

    clk = convertScapyTimeToFloat(packets[0].time)
    show_interfaces()
    #print(get_if_list())
    s = conf.L2socket(iface=sending_interface)

    for (idx, p) in enumerate(packets):
        print(f"{idx+1}/{len(packets)}")
        timer = convertScapyTimeToFloat(p.time)
        time.sleep(timer-clk)
        clk = convertScapyTimeToFloat(p.time)
        if p.len >= 9:
            payload = bytearray(p.load)
            t = time.time()
            b = struct.pack('d', t)
            payload[0:8] = b
            payload[9]   = coloNodeID
            t2 = time.time()

            p["IP"].dest   = ip_dest
            p["UDP"].dport = port_dest
            p["Raw"].load  = payload
            s.send(p)

pcap = sys.argv[1]
iface = sys.argv[2]
ipdest = sys.argv[3]
portdest = sys.argv[4]
nodeId   = sys.argv[5]

print(sys.argv)

replay_pcap_udp(pcap, iface, ipdest, int(portdest), int(nodeId))
