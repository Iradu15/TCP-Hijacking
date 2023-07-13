from flask import Flask, jsonify
from flask import request
import requests
from scapy.all import *
import socket

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello World!"

'''
This method expects a json content.
Use header: 'Content-Type: application/json'
'''
@app.route('/post', methods=['POST'])
def post_method():
    print("Got from user: ", request.get_json())
    requestedDomain = request.get_json()['value']

    # dns_query = DNS(rd=1, qd=DNSQR(qname=requestedDomain, qtype='A'))

    # # Convert the DNS query message to a byte string
    # dns_query_bytes = bytes(dns_query)

    # # Send the DNS query message to the UDP socket
    # simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # simple_udp.sendto(dns_query_bytes, ('localhost', 53))

    # # Receive the response from the UDP socket
    # response, server_address = simple_udp.recvfrom(4096)
    
    # DNS request to your DNS server
    ip = IP(dst='198.8.0.3')  # Replace with the IP address of your DNS server
    transport = UDP(dport=53)  # Replace with the port number of your DNS server

    # rd = 1 cod de request
    dns = DNS(rd=1)

    # query pentru a afla entry de tipul 
    dns_query = DNSQR(qname=requestedDomain, qtype=1, qclass=1)
    dns.qd = dns_query

    answer = sr1(ip / transport / dns)

    return jsonify({'got_it': answer[DNS].summary()})

@app.route('/<name>')
def hello_name(name):
    return "Hello {}!".format(name)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001)
