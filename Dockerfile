FROM python:alpine
MAINTAINER xi4okv "xi4okui@gmail.com"

RUN apk update 
RUN apk add gcc python3-dev 
RUN apk --no-cache add  musl-dev

RUN pip install requests gevent -i https://mirrors.aliyun.com/pypi/simple/

WORKDIR /opt

ADD xkscan.py xkscan.py

ADD lib lib

ENTRYPOINT python xkscan.py
