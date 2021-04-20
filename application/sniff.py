#!/usr/bin/env python3
import sys
from scapy.all import *
import mysql.connector
from prometheus_client import Counter, start_http_server


def db_conn():
    connection = mysql.connector.connect(
        host = "mysql57",
        user = "root",
        password = "password",
        database = "portstraffic"
    )
    return connection


def insert_values(ts, dst, dport):
    conn = db_conn()
    mycursor = conn.cursor()
    mycursor.execute(f"INSERT INTO tcptraffic (TS, Dest_IP, Dest_Port) VALUES('{ts}','{dst}','{dport}')")
    conn.commit()
    conn.close()


def processing(pkt):
    global REQUEST_COUNTER
    TSval = dest_port = 0
    dest_IP = ''
    if hasattr(pkt.payload, 'dport'):   #Check for dport
        dest_port = pkt.dport
        REQUEST_COUNTER.labels(dest_port).inc()
    if pkt.haslayer(IP):    #Check for IP layer
        dest_IP = pkt[IP].dst
    if pkt.haslayer(TCP):   #check for TCP layer
        for opt, val in pkt[TCP].options:
            if opt == 'Timestamp':
                TSval, TSecr = val
    insert_values(TSval, dest_IP, dest_port)    #Insert values to database


if __name__ == '__main__':

    #Check argv for bad input
    ports = ""
    if len(sys.argv) > 1 and  all(True if item.isnumeric() else False for item in sys.argv[1:]):
        if all([True for item in sys.argv[1:] if 0>=int(item)<=65353]):
            for i in range(1,len(sys.argv)):
                if i == 1:
                    ports += f"port {sys.argv[1]}"
                else:
                    ports += f" or port {sys.argv[i]}"
            print(f"Intercepts traffic on ports", *sys.argv[1:])
        else:
            print("Ports must be in range [0-65353]")
            exit()
    elif len(sys.argv)>1 and not all(True if item.isnumeric() else False for item in sys.argv[1:]):
        print("Ports must be integers in range [0-65353]")
        exit()
    else:
        ports = "port 80"
        print("Default port set to 80")

    #Build port counter metric
    REQUEST_COUNTER = Counter('requests_at_endpoint', 'Number of request at an endpoint', ['endpoint'])

    #HTTP server for Prometheus
    start_http_server(8000)

    #Start sniffing packets
    sniff(iface="eth0", filter=ports, prn=lambda pkt: processing(pkt))
