class SLEB128Decoder:
    def __init__(self, buffer, size):
        self.buffer = buffer
        self.current = 0
        self.count = len(buffer)
        self.size = size

    def pop_front(self):
        shift = 0
        value = 0
        b = 0
        while True:
            if self.current > self.count:
                raise Exception("SLEB128Decoder ran out of bounds")
            b = self.buffer[self.current] & 0xff
            self.current += 1
            value |= ((b & 0x7f) << shift)
            shift += 7
            if (b & 0x80) == 0:
                break
        if shift < self.size and (b & 0x40) != 0:
            value |= -(1 << shift)
        return value
