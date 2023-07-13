def interpret_DNS_qtype(type):
    """
    A: domain name -> ipv4
    NS: domain name -> authoritative nameservers
    CNAME: domain name -> domain name 
    """
    match type:
        case 1:
            return "A"
        case 2:
            return "NS"
        case 5:
            return "CNAME"
        case 15:
            return "MX"
        case 28:
            return "AAAA"
        case _:
            return "UNKNOWN"


def display_DNS_query(DNS_packet):
    domain_requested = DNS_packet.qd.qname.decode()[:-1]
    record_type = interpret_DNS_qtype(DNS_packet.qd.qtype)

    print("=========================")
    print("DNS request")
    print("=========================")
    print(f"| Request ID: {DNS_packet.id}")
    print(f"| Domain: {domain_requested}")
    print(f"| Record type: {record_type}")
    print("=========================")
    print()

def display_DNS_response(DNS_packet):
    print("=========================")
    print("DNS response")
    print("=========================")
    print(f"| Request ID: {DNS_packet.id}")
    print(f"| QR: {DNS_packet.qr}")
    print(f"| Operation code: {DNS_packet.opcode}")
    print(f"| Response code: {DNS_packet.rcode}")
    print(f"| QDcount: {DNS_packet.qdcount}")
    print(f"| ANcount: {DNS_packet.ancount}")
    print(f"| NScount: {DNS_packet.nscount}")
    print(f"| ARcount: {DNS_packet.arcount}")
        
    print("-------------------------")
    print("|| Questions: ")
    print("-------------------------")
    if DNS_packet.qd:
        DNS_packet.qd.show()

    print("-------------------------")
    print("|| Answers: ")
    print("-------------------------")
    if DNS_packet.an:
        DNS_packet.an.show()

    print("-------------------------")
    print("|| Authority: ")
    print("-------------------------")
    if DNS_packet.ns:
        DNS_packet.ns.show()

    print("-------------------------")
    print("|| Additional: ")
    print("-------------------------")
    if DNS_packet.ar:
        DNS_packet.ar.show()
    
    print("=========================")
    print()
