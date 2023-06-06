from ospf_scapy import *
from hashlib import md5
from sys import argv, stderr, executable, exit

if len(argv) != 3:
    print("USAGES:", executable, argv[0], "[pcap/pcapng file path]", "[wordlist file path]", file=stderr)
    exit(1)

pkts = rdpcap(argv[1])

pkts = [raw(x[2]) for x in pkts if x[2].__class__.__name__.startswith('OSPF')]
pkts = [(pkt[:48], pkt[48:64]) for pkt in pkts]

with open('ospf_packets.hash.john', 'w') as file:
    [file.write(f'$netmd5${pkt[0].hex()}${pkt[1].hex()}\n') for pkt in pkts]

counter = 0

with open(argv[2], 'rb') as file:
    for password in file:
        password = password[:-1]
        for pkt in pkts:
            if md5(pkt[0] + password).digest() == pkt[1]:
                print('[+]', pkt[0].hex(), pkt[1].hex(), password.decode())
                counter += 1
                if counter == len(pkts):
                    print('[+] Done !')