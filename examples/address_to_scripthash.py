#! /usr/bin/env python3
#
# convert address to scripthash
#
import argparse
from connectrum.utils import address_to_scripthash

parser = argparse.ArgumentParser()
parser.add_argument("address", help="want to convert address",
                    type=str)
args = parser.parse_args()
print(address_to_scripthash(args.address))
