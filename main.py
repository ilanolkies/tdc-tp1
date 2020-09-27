#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.l2 import Ether
import numpy as np

S1 = {}


def mostrar_fuentes(S):
    N = sum(S.values())
    if N%10!=0:
        return
    simbolos = sorted(S.items(), key=lambda x: -x[-1])
    entropia = 0
    broadcast = 0
    unicast = 0
    print("Paquetes capturados : %.i" % N)
    for d, k in simbolos:
        print("%s : %.5f : %.5f bits" % (d, k / N, -np.log2(k/N)))
        entropia -= (k/N)*np.log2(k/N)
        if d[0] == "BROADCAST":
            broadcast += k/N
        else:
            unicast += k/N
    print("Entropia: %.5f" % entropia)
    print("BROADCAST : %.2f%%" % (100*broadcast))
    print("UNICAST : %.2f%%\n" % (100*unicast))


def callback(pkt):
    if pkt.haslayer(Ether):
        dire = "BROADCAST" if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff" else "UNICAST"
        proto = pkt[Ether].type
        s_i = (dire, proto)
        if s_i not in S1:
            S1[s_i] = 0.0

        S1[s_i] += 1.0
    mostrar_fuentes(S1)


sniff(prn=callback)
