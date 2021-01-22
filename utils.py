import struct


def unpack(stream, fmt):
    size = struct.calcsize(fmt)
    buf = stream.read(size)
    return struct.unpack(fmt, buf)


def unpack2(buf, idx, fmt):
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, buf[idx:idx + size])

