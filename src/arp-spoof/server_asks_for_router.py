from scapy.all import * 

# trimite un request ARP broadcast pentru a invata adresa MAC a routerului
send(ARP(op=1, pdst="198.7.0.1", hwdst="ff:ff:ff:ff:ff:ff"))