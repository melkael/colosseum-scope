from scapy.all import *
import struct
import time
import sys

def convertScapyTimeToFloat(a):
    return float(repr(a)[9:-2])

def replay_pcap_udp(pcap, sending_interface, ip_dest, port_dest, coloNodeID):
    packets = PcapNgReader(pcap)
    first_packet = next(packets)


    # we reload because we want to include the first packet too
    packets = PcapNgReader(pcap)

    clk = convertScapyTimeToFloat(first_packet.time)
    show_interfaces()
    #print(get_if_list())
    s = conf.L2socket(iface=sending_interface)

    for (idx, p) in enumerate(packets):
        print(f"{idx+1}")
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
            s.send(IP(dst=ip_dest)/UDP(dport=port_dest)/Raw(load=payload))


pcap = sys.argv[1]
iface = sys.argv[2]
ipdest = sys.argv[3]
portdest = sys.argv[4]
nodeId   = sys.argv[5]

print(sys.argv)

replay_pcap_udp(pcap, iface, ipdest, int(portdest), int(nodeId))
