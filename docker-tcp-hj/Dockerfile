FROM snisioi/retele:2021

COPY ./*.sh ./
COPY ./tcp_client.py ./
COPY ./tcp_server.py ./
COPY /tcp-hj/main.py ./
COPY /arp-spoof/main_ARP.py ./
COPY /tcp-hj/router_pingARP.py ./

# RUN apt-get update && apt-get install -y python3 python3-pip


# RUN apt-get update && apt-get install -y iptables iproute2 libnetfilter-queue-dev
# RUN pip3 install --upgrade python-iptables cython

# RUN apt-get install -y python-dev
# RUN apt-get install -y build-essential python3-dev libnetfilter-queue-dev


# RUN pip3 install flask
# RUN pip3 install scapy
# RUN pip3 install requests