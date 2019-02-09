#!/usr/bin/env python
import sys
from itertools import product

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

if __name__ == '__main__':
    run = True
    if len(sys.argv) == 2:
        dictionary = [sys.argv[1]]
    elif len(sys.argv) > 2:
        with open(' '.join(sys.argv[2:]),"r") as f:
            dictionary = f.readlines()
    else:
        print("usage:")
        print("\t./leet.py <word>")
        print("\t./leet.py -f <dictionary_file>\n")
        run = False
    if run:
        for word in dictionary:
            branches = [set(leet.get(c.lower(),[c])+[c,c.upper(),c.lower()]) for c in word]
            for mangled in product(*branches):
                print(''.join(mangled))