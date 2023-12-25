#!/usr/bin/python3

import ipaddress

class IPTrie:
    def __init__(self, up=None):
        self.children = [ None, None ]
        self.local = None
        self.up = up
        self.buckets = set()

    def add(self, network, bit=0):
        if network.prefixlen == bit:
            self.local = network
            self.buckets.add(network.bucket)
            return
        
        pos = (int(network[0]) >> (network.max_prefixlen - bit - 1)) & 1

        if self.children[pos] is None:
            self.children[pos] = IPTrie(self)

        self.children[pos].add(network, bit + 1)

    def dump(self, path=[]):
#        return \
#                (f"{''.join([ str(x) for x in path])}: {self.local} | buckets = {self.buckets}\n" if self.local or len(self.buckets) > 1 else "") + \

        return \
                (str(self.local) + "\n" if self.local or len(self.buckets) > 1 else "") + \
                (self.children[0].dump([ *path, 0 ]) if self.children[0] is not None else "") + \
                (self.children[1].dump([ *path, 1 ]) if self.children[1] is not None else "")

    def aggregate(self, up=None, net=ipaddress.IPv6Network("::/0"), covered=None):
        if self.children[0] is None and self.children[1] is None:
            return self

        if self.local:
            covered = self.local
        else:
            assert(covered is not None)

        def coveredNode(bit):
            t = IPTrie(self)
            t.local = AgrPointv6(list(net.subnets())[bit], covered.bucket)
            t.buckets.add(covered.bucket)
            return t

        nap = IPTrie(up)
        sn = list(net.subnets())
        ac = [
                coveredNode(b) if self.children[b] is None
                else self.children[b].aggregate(nap, sn[b], covered)
                for b in (0, 1)
                ]

        nap.children = ac

        intersection = ac[0].buckets & ac[1].buckets

        if len(intersection) > 0:
            nap.local = AgrPointv6(net, sorted(intersection)[0])
            nap.buckets = intersection
        else:
            nap.buckets = ac[0].buckets | ac[1].buckets
            nap.local = None

#        print(self.children, sn, ac, self.local, nap.local, covered.bucket)
        return nap

    def reduce(self, covered):
        if covered is None:
            return self

        elif self.local is None:
            return None

        elif self.local.bucket == covered.bucket:
            return None

        else:
            return self

    def prune(self, up=None, net=ipaddress.IPv6Network("::/0"), covered=None):
        if self.children[0] is None and self.children[1] is None:
            r = self.reduce(covered)
#            print(f"Prune NR at {net}, C {covered}, L {self.local} -> {r}")
            return r

        loc = covered if self.local is None else self.local
        assert(loc)
        sn = list(net.subnets())
        nap = IPTrie(up)
        nap.children = [ None if self.children[b] is None else self.children[b].prune(nap, sn[b], loc) for b in (0,1) ]
        if net.prefixlen == 0 or self.local is not None and self.local.bucket != covered.bucket:
            nap.local = self.local

        if nap.children[0] is None and nap.children[1] is None:
            r = nap.reduce(covered)
#            print(f"Prune AR at {net}, C {covered}, L {self.local}, ORIG-CH {self.children} -> {r}")
            return r
        else:
#            print(f"Prune PL at {net}, C {covered}, L {self.local} ({nap.local})")
            return nap

class AgrPointv6(ipaddress.IPv6Network):
    def __init__(self, net, bucket):
        super().__init__(net)
        self.bucket = bucket

    def __str__(self):
#        print(type(self), super().__str__(), type(self.bucket), self.bucket)
        return super().__str__() + " -> " + self.bucket

# Load
t = IPTrie()

try:
    while p := input():
        data = p.split(" ")
        t.add(AgrPointv6(data[0], data[1]))
except EOFError:
    pass

# Dump
print("Dump After Load")
print(t.dump())

tt = t.aggregate()
#print("Dump After Aggr")
#print(tt.dump())

ttt = tt.prune()
print("Dump After Prune")
print(ttt.dump())
