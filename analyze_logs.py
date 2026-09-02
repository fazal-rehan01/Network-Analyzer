import os

print("\n" + "="*60)
print("       AUTOMATED ZEED & PACKET FORENSIC SUMMARY")
print("="*60 + "\n")

# Process HTTP Logs
if os.path.exists("http.log"):
    print("[!] ALERT: Analyzing Unencrypted HTTP Traffic...")
    with open("http.log", "r") as f:
        for line in f:
            if not line.startswith("#"):
                parts = line.split("\t")
                if len(parts) > 9:
                    print(f"    - Method: {parts[7]} | Host: {parts[8]} | URI: {parts[9]}")

# Process DNS Logs
if os.path.exists("dns.log"):
    print("\n[!] ALERT: Suspected DNS Exfiltration/Tunneling:")
    with open("dns.log", "r") as f:
        for line in f:
            if not line.startswith("#"):
                parts = line.split("\t")
                if len(parts) > 9:
                    print(f"    - Queried Domain: {parts[9]}")

# Process Connection Logs
if os.path.exists("conn.log"):
    print("\n[!] Connection Summary (Port Activity Count):")
    ports = []
    with open("conn.log", "r") as f:
        for line in f:
            if not line.startswith("#"):
                parts = line.split("\t")
                if len(parts) > 5:
                    ports.append(parts[5])
    print(f"    - Total Unique Target Ports Contacted: {len(set(ports))}")

print("\n" + "="*60 + "\n")
