FROM python:alpine
MAINTAINER xi4okv "xi4okui@gmail.com"

RUN apk update 
RUN apk add nmap
RUN pip install python-nmap celery redis

WORKDIR /opt

ADD xkscan.py xkscan.py

ENV BROKER None

ENTRYPOINT celery -A xkscan worker --loglevel=info -c 10
