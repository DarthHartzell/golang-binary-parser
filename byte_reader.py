
import struct

class ByteReader(object):
    def __init__(self, arr):
        self.offset = 0
        self.buffer = bytearray()
        self.SEEK_START = 0
        self.SEEK_CURRENT = 1
        self.SEEK_END = 2
        self.buffer[:] = arr

    def read_32( self ):
        ret = struct.unpack("<I", self.buffer[self.offset:self.offset+4])[0]
        self.offset = self.offset + 4
        return ret
    
    def read_64( self ):
        ret = struct.unpack("<Q", self.buffer[self.offset:self.offset+8])[0]
        self.offset = self.offset + 8
        return ret
    
    def seek( self, off, flag ):
        if flag == self.SEEK_START:
            self.offset = off
        elif flag == self.SEEK_CURRENT:
            self.offset = self.offset + off
        else:
            print("implement me")

    def read_8(self):
        ret = self.buffer[self.offset]
        self.offset = self.offset + 1
        return ret

    def read_16( self ):
        ret = struct.unpack("<H", self.buffer[self.offset:self.offset+2])[0]
        self.offset = self.offset + 2
        return ret