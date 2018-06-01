import redis
import nmap
import os
from celery import Celery

if "BROKER" in os.environ:
    BROKER = os.environ["BROKER"]
else:
    BROKER = None
    
BROKER_URL = 'redis://' + BROKER + '/0'
BACKEND_URL = 'redis://' + BROKER + '/1'

celery = Celery('xkscan',
    broker=BROKER_URL,
    backend=BACKEND_URL)

@celery.task
def scan(target):
    nm = nmap.PortScanner()
    result = nm.scan(hosts=target, arguments='-sS -p 1-65535')
    return result
