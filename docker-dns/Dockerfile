FROM python:latest

LABEL Maintainer="radu"

ADD docker-dns/requirements.txt .
RUN pip3 install -r requirements.txt && \
    rm requirements.txt

COPY ./ ./
RUN apt-get update && apt-get install -y dnsutils
