FROM python:alpine
MAINTAINER xi4okv "xi4okui@gmail.com"

RUN pip install requests gevent

WORKDIR /opt

ADD xkscan.py xkscan.py

ADD lib lib

ENTRYPOINT python zoomeye.py
