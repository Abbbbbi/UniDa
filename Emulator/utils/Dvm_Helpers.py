from numpy import int32


def hashCode(s):
    seed = 31
    h = 0
    for c in s:
        h = int32(seed * h) + ord(c)
    return h
