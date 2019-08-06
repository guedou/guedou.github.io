# Guillaume Valadon <guillaume@valadon.net>

import argparse                                                                 
                                                                                
from scapy.all import *                                                         
                                                                                
parser = argparse.ArgumentParser(description="A simple ping6")                  
parser.add_argument("ipv6_host", help="An IPv6 address")
args = parser.parse_args()                                                      
                                                                                
print(sr1(IPv6(dst=args.ipv6_host) / ICMPv6EchoRequest(), verbose=0).summary())
