from scapy.all import ARP, sniff
import datetime
import winsound

# ==============================
# ARP Spoof Detector 
# Author: Khaled T. A.
# ==============================

log_file = "arp_spoof_log.txt"


known_devices = {}

def log_attack(ip, old_mac, new_mac):
    time_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_msg = (
        f"[{time_now}] ALERT! Possible ARP Spoof detected!\n"
        f"IP Address : {ip}\n"
        f"Old MAC    : {old_mac}\n"
        f"New MAC    : {new_mac}\n"
        f"--------------------------------------\n"
    )

    print(alert_msg)

    with open(log_file, "a") as f:
        f.write(alert_msg)

   
    winsound.Beep(1200, 300)


def detect(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

       
        if ip in known_devices:
            if known_devices[ip] != mac:
                log_attack(ip, known_devices[ip], mac)
        else:
            
            known_devices[ip] = mac


print("======================================")
print(" ARP Spoof Detector by Khaled T. A.")
print("======================================")
print("Listening for ARP packets...\n")

sniff(store=False, prn=detect)
