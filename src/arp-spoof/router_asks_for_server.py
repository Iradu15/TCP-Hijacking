from scapy.all import * 

# trimite un request ARP broadcast pentru a invata adresa MAC a serverului
send(ARP(op=1, pdst="198.7.0.2", hwdst="ff:ff:ff:ff:ff:ff"))