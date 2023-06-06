# OSPF Bruteforce MD5 Authentication

## Description

This repository performs a dictionnary attacks against OSPF MD5 authentication using scapy. 

## Requirements

 - python3
 - python3 Standard Library
 - scapy
 - scapy_ospf-v0.91.py

## Installation

```bash
git clone https://github.com/mauricelambert/OSPF_bruteforce.git
cd OSPF_bruteforce
python3 -m pip install scapy
wget https://raw.githubusercontent.com/wiki/secdev/scapy/attachments/Code/OSPF/scapy_ospf-v0.91.py -o scapy_ospf.py
```

## Usages

```bash
python3 ospf_bruteforce.py [pcap/pcapng file path] [wordlist file path]

python3 ospf_bruteforce.py ospf_authentication_hash.pcapng /usr/share/wordlists/rockyou.txt
# OR
chmod u+x ospf_bruteforce.py
./ospf_bruteforce.py ospf_authentication_hash.pcapng /usr/share/wordlists/rockyou.txt
```

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
