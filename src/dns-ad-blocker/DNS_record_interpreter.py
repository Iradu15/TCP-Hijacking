import random
from random import randrange
from scapy.all import *
from scapy.layers.dns import IP, UDP, DNS, DNSQR, DNSRR
from blacklists.blacklist_parser import get_adservers_list, get_ad_blocker_response

adservers = get_adservers_list("src/dns-ad-blocker/blacklists/adservers.txt") 
facebook = get_adservers_list("src/dns-ad-blocker/blacklists/facebook.txt")
root_servers_IP = ["192.36.148.17", "192.58.128.30", "192.5.5.241"] 

def send_response_server_error(DNS_packet):
    """Sent when an error occurs"""
    DNS_error_response = DNS(
            id = DNS_packet[DNS].id,
            qr = 1,
            aa = 0,
            rcode = 2,
            qd = DNS_packet.qd
        )
    
    return DNS_error_response

def send_request_root_server(DNS_packet):
    """
    Sends a DNS request packet to a randomly chosen root server.    
    If successful, returns a response from the root server or a response from a TLD server if necessary.
    If unsuccessful, returns a server error response.
    """
    # choose one random server from the root ones
    root_ip = IP(dst = random.choice(root_servers_IP))
    transport = UDP(dport = 53)

    # root servers do not offer recursivity
    DNS_packet.rd = 0
    
    root_response = sr1(root_ip / transport / DNS_packet, verbose = 0, timeout = 2)

    if root_response:
        # code contains error 
        if root_response[DNS].rcode != 0:
            return root_response

        # There must be at least 2 additional responses, because there is a case 
        # where there might be only one, and that one might be of type OPT, 
        # which contains some additional information.
        if root_response.arcount > 1:
            ar_cnt = randrange(root_response.arcount)

            while root_response.ar[ar_cnt].type != 1:
                ar_cnt = randrange(root_response.arcount)

            resp = root_response.ar[ar_cnt]

        else:
            # If there are no additional answers, we need to search for the 
            # name of an NS (Name Server) that knows how to handle this request.
            ns_cnt = randrange(root_response.nscount)
            resp = root_response.ns[ns_cnt]

            # NS type request to google to get the desired NS record
            DNSRR_auth_query = DNSQR(qname = resp.rdata, qtype = 1, qclass = 1)
            DNSRR_auth_IP = sr1(IP(dst = '8.8.8.8') / UDP(dport = 53) / DNS(qd = DNSRR_auth_query, rd=1), verbose = 0, timeout = 2)
            resp = DNSRR_auth_IP[DNS].an

        return send_request_tld_server(DNS_packet, resp.rdata)
        # In case the TLD server does not return a response,
        # we send a response indicating that the request could not be resolved by the server.

    return send_response_server_error(DNS_packet)

def send_request_tld_server(DNS_packet, TLD_ip):
    """
    Sends a DNS request packet to the Top-Level Domain (TLD) server.
    If successful, returns a response from the TLD server or a response from an authoritative server if necessary.
    If unsuccessful, returns a server error response.
    """
    TLD_IP = IP(dst=TLD_ip)
    transport = UDP(dport=53)

    # Send DNS packet to the TLD server and receive response
    TLD_response = sr1(TLD_IP / transport / DNS_packet, verbose=0, timeout=2)

    if TLD_response:
        # Check if the response contains errors
        if TLD_response[DNS].rcode != 0:
            return TLD_response

        # Check if the TLD returns the desired record(s)
        if TLD_response.ancount > 0:
            return TLD_response

        # Ensure there are at least 2 additional responses, as there might be only one, possibly of type OPT, which contains additional information
        elif TLD_response.arcount > 1:
            ar_cnt = randrange(TLD_response.arcount)

            while TLD_response.ar[ar_cnt].type != 1:
                ar_cnt = randrange(TLD_response.arcount)

            resp = TLD_response.ar[ar_cnt]
        else:
            # If there are no additional answers, search for the name of an NS (Name Server) that knows how to handle this request
            ns_cnt = randrange(TLD_response.nscount)
            DNSRR_auth = TLD_response.ns[ns_cnt]

            # If we receive a record of type SOA, it means that the request was not fulfilled, so we need to return this response
            if DNSRR_auth.type == 6:
                return TLD_response

            # A request to the Google server which will return the desired NS
            DNSRR_auth_query = DNSQR(qname=DNSRR_auth.rdata, qtype=1, qclass=1)
            DNSRR_auth_IP = sr1(IP(dst='8.8.8.8') / UDP(dport=53) / DNS(qd=DNSRR_auth_query, rd=1), verbose=0, timeout=2)

            if DNSRR_auth_IP is None:
                return DNSRR_auth_IP

            resp = DNSRR_auth_IP[DNS].an

        # Forward the request to the authoritative server
        return send_request_authoritative_server(DNS_packet, resp.rdata)
    else:
        # If the TLD server does not return a response, send a response indicating that the request could not be resolved by the server
        return send_response_server_error(DNS_packet)

def send_request_authoritative_server(DNS_packet, authoritative_ip):
    """
    Sends a DNS request packet to the authoritative server.
    If successful, returns a response from the authoritative server.
    If unsuccessful, returns None.
    """
    auth_IP = IP(dst=authoritative_ip)
    transport = UDP(dport=53)

    # Send DNS packet to the authoritative server and receive response
    authoritative_resp = sr1(auth_IP / transport / DNS_packet, verbose=0, timeout=2)

    if authoritative_resp:
        # If the request is not of type NS but the response is, 
        # it means we need to search in one of the received NS for the queried domain
        if DNS_packet.qd.qtype != 2 and authoritative_resp.nscount > 0 and authoritative_resp.an is None:
            # While the authority returns NS and not A, we ask Google for the address of the NS and then ask further at the NS address
            while authoritative_resp and authoritative_resp.nscount > 0 and authoritative_resp.ns.type == 2 and authoritative_resp.an is None:
                DNS_req = DNS(rd=1)  # to be recursive
                DNS_req_qd = DNSQR(qname=authoritative_resp.ns.rdata, qtype=1, qclass=1)  # the server's name
                DNS_req.qd = DNS_req_qd  # look for the IP of the server's name

                # To find the IP of the NS, send a request to Google
                authoritative_resp = sr1(IP(dst='8.8.8.8') / UDP(dport=53) / DNS_req, verbose=0, timeout=2)
                # To find the IP of the domain, send a request to the NS server we found in the previous step
                authoritative_resp = sr1(IP(dst=authoritative_resp.an.rdata) / UDP(dport=53) / DNS_packet[DNS], verbose=0, timeout=2)
                
        # If the request is of type A / AAAA, 
        # check if the received record is CNAME, and if it is, 
        # recursively send a request to our server to return the IP address for that CNAME
        if (DNS_packet.qd.qtype == 1 or DNS_packet.qd.qtype == 28) and authoritative_resp.an and authoritative_resp.an.type == 5:
            DNS_req = DNS()
            DNS_req_qd = DNSQR(qname=authoritative_resp.an.rdata, qtype=DNS_packet.qd.qtype, qclass=1)
            DNS_req.qd = DNS_req_qd

            return send_request_root_server(DNS_req)
    
    return authoritative_resp

def google_request(DNS_packet):
    return sr1(IP(dst = '8.8.8.8') / UDP(dport = 53) / DNS_packet, verbose = 0)

def single_record_lookup(DNS_packet):
    domain_requested = DNS_packet.qd.qname.decode()[:-1]

    if domain_requested in adservers or domain_requested in facebook:
        return get_ad_blocker_response(DNS_packet)

    response = send_request_root_server(DNS_packet)

    # if found, the answer needs to be filtered
    if response:
        DNS_response = response[DNS]
        DNS_response.id = DNS_packet[DNS].id    # answer's ID needs to be the same as the initial request from our server
        DNS_response.aa = 0                     # can't say we are authoritative answer
        DNS_response.qd = DNS_packet.qd         # answer's query needs to be the same as the initial request from our server

        return DNS_response
    
    else:
        return send_response_server_error(DNS_packet)
    
def multiple_records_lookup(DNS_packet):
    domain_requested = DNS_packet.qd.qname.decode()[:-1]

    if domain_requested in adservers or domain_requested in facebook:
        return get_ad_blocker_response(DNS_packet)
    
    response = send_request_root_server(DNS_packet)

    if response:
        DNS_response = response[DNS]
        DNS_response.id = DNS_packet[DNS].id
        DNS_response.aa = 0    
        DNS_response.qd = DNS_packet.qd 

        if DNS_response.rcode == 0 and DNS_response.ancount > 0:
            for answer in range(DNS_response.ancount):
                NS_domain = DNS_response.an[answer].rdata.decode()[:-1] if DNS_packet.qd.qtype == 2 else DNS_response.an[answer].exchange.decode()[:-1]

                if NS_domain in adservers or NS_domain in facebook:
                    return get_ad_blocker_response(DNS_packet)

        return DNS_response
    
    else:
        return send_response_server_error(DNS_packet)