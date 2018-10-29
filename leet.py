#!/usr/bin/env python

from itertools import product
import sys

dictionary = ["password"]

if len(sys.argv) > 1:
    with open(sys.argv[1],"r") as f:
        dictionary = f.readlines()

leet = {'a':['@','4'],
        'c':['k'],
        'e':['3'],
        'g':['9'],
        'i':['1'],
        'l':['1'],
        'o':['0'],
        's':['5'],
        't':['7'],
        'u':['oo','00'],
        'y':['j']}

for word in dictionary:
    branches = [set(leet.get(c.lower(),[c])+[c,c.upper(),c.lower()]) for c in word]
    for mangled in product(*branches):
        print(''.join(mangled))
