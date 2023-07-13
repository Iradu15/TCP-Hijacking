import socket
from scapy.all import *
from scapy.layers.dns import DNS, UDP, IP

import DNS_record_interpreter
from DNS_record_display import display_DNS_query, display_DNS_response

# create IPv4, UDP socket
simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
simple_udp.bind(('0.0.0.0', 53))

try: 
    while True:
        request, source_address = simple_udp.recvfrom(65535)
        print('source address', source_address)
        packet = DNS(request)
        dns = packet.getlayer(DNS)
        
        # Only process DNS requests 
        if dns and dns.opcode == 0 and dns.qr == 0: 
            display_DNS_query(dns)

            # A | CNAME | AAA types
            if dns.qd.qtype in [1, 5, 28]:
                dns_response = DNS_record_interpreter.single_record_lookup(dns)
            
            # NS | MX types
            elif dns.qd.qtype in [2, 15]:
                dns_response = DNS_record_interpreter.multiple_records_lookup(dns)
                
            # Let google hande it otherwise
            else:
                dns_response = sr1(IP(dst = '8.8.8.8') / UDP(dport = 53) / dns, verbose = 0)
            
            display_DNS_response(dns_response)
            simple_udp.sendto(bytes(dns_response), source_address)

finally: 
    simple_udp.close()