# CS 6349 – Homework 3: Network Traffic Analysis (IcedID pcap)

Worked solution for the three-part HW3 using the same capture,
`2023-07-25-IcedID-infection-traffic-1.pcap` (malware-traffic-analysis.net, 2023-07-25 IcedID infection;
SHA-256 `45a6bb62e2b62bce16559919876392b017b5156c6b843dc6412512e81da3e813`, not stored in this repo).

| Part | Tool | Report | Key result |
|---|---|---|---|
| 3.1 | Zeek 7.0.11 | [HW3.1_Zeek/HW3.1_Zeek_Report.pdf](HW3.1_Zeek/HW3.1_Zeek_Report.pdf) | IcedID infection of 10.7.25.101; C2 2.56.177.122 beaconing every ~303 s; self-signed C2 cert |
| 3.2 | Suricata 7.0.3 + ET Open | [HW3.2_Suricata/HW3.2_Suricata_Report.pdf](HW3.2_Suricata/HW3.2_Suricata_Report.pdf) | 47 ET alerts (2 IcedID MALWARE, 45 self-signed-cert TLS); custom rule fired 87× |
| 3.3 | Wireshark 4.2.2 | [HW3.3_Wireshark/HW3.3_Wireshark_Report.pdf](HW3.3_Wireshark/HW3.3_Wireshark_Report.pdf) | TLS = 69.9 % of bytes; 1 MB fake-gzip IcedID payload exported & hashed; C2 + BackConnect channels |

## Reproduce
```bash
# 3.1 Zeek
zeek -r 2023-07-25-IcedID-infection-traffic-1.pcap                       # TSV logs
zeek -r 2023-07-25-IcedID-infection-traffic-1.pcap LogAscii::use_json=T  # JSON logs
python3 HW3.1_Zeek/analyze_zeek.py                                        # run inside the log folder

# 3.2 Suricata
suricata -S emerging-all.rules -r 2023-07-25-IcedID-infection-traffic-1.pcap -l output/
suricata -S HW3.2_Suricata/local.rules -r 2023-07-25-IcedID-infection-traffic-1.pcap -l output_custom/

# 3.3 Wireshark: open the pcap, apply filters from HW3.3_Wireshark/display_filters.txt
# PDFs are built from the .md files with: python3 build_pdf.py <report.md> <report.pdf>
```

## Indicators of compromise
173.232.146.10 · www.sophrologie-yoga.fr (109.234.165.110) · filtaferamoza.com (128.199.3.164) ·
magizanqomo.com / magiketchinn.com (2.56.177.122) · 165.232.175.216:443 ·
lohmotarufos.com / flarkonafaero.com (140.99.221.138) · C2 cert serial D4B36C ·
payload SHA-256 729a9743319f548134a1535291bea0bfdac6cd9a8c4c9ba19ab1b8524d5ebea7

> Safety: only the pcap was analyzed. The exported payload was hashed in an isolated folder and deleted; no malware is stored here.
