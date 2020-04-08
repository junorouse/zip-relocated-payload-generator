#!/usr/bin/env python
# 
# The zip relocator - used for stuffs like embedding zips in executable file (SFX!) or LFI exploits (the purpose for which this is created)
# Created by luke1337
#
#
#            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#                    Version 2, December 2004
#
# Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>
#
# Everyone is permitted to copy and distribute verbatim or modified
# copies of this license document, and changing it is allowed as long
# as the name is changed.
#
#            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
#
#  0. You just DO WHAT THE FUCK YOU WANT TO.
#

import struct
from collections import namedtuple

class ZipLF(namedtuple('ZipLF_', ('ver_req', 'flag', 'compression', 'mtime', 'mdate', 'crc32', 'sz_compr', 'sz_uncompr', 'sz_filename', 'sz_extra', 'filename', 'extra'))):
    signature = b'PK\x03\x04'
    length = 30
    pack = "<HHHHHLLLHH"
    
    @classmethod
    def parse(cls, hdr):
        if hdr[:4] != cls.signature:
            raise ValueError("Invalid signature")
        dt = struct.unpack(cls.pack, hdr[4:30])
        filename = hdr[30:30+dt[10]]
        extra = hdr[30+dt[10]:30+dt[10]+dt[11]]
        inst = cls(*dt, filename=filename, extra=extra)
        inst.length = 30 + dt[10] + dt[11]
        return inst

    def encode(self):
        return self.signature + struct.pack(self.pack, *self[:10]) + self.filename + self.extra

class ZipCD(namedtuple('ZipCD_', ('ver_created', 'ver_req', 'flag', 'compression', 'mtime', 'mdate', 'crc32', 'sz_compr', 'sz_uncompr', 'sz_filename', 'sz_extra', 'sz_comment', 'lf_disk', 'int_attr', 'ext_attr', 'lf_offset', 'filename', 'extra', 'comment'))):
    signature = b'PK\x01\x02'
    length = 46
    pack = "<HHHHHHLLLHHHHHLL"

    @classmethod
    def parse(cls, hdr):
        if hdr[:4] != cls.signature:
            raise ValueError("Invalid signature")
        dt = struct.unpack(cls.pack, hdr[4:46])
        filename = hdr[46:46+dt[9]]
        extra = hdr[46+dt[9]:46+dt[9]+dt[10]]
        comment = hdr[46+dt[9]+dt[10]:46+dt[9]+dt[10]+dt[11]]
        inst = cls(*dt, filename=filename, extra=extra, comment=comment)
        inst.length = 46+dt[9]+dt[10]+dt[11]
        return inst

    def encode(self):
        return self.signature + struct.pack(self.pack, *self[:16]) + self.filename + self.extra + self.comment

class ZipEOCD(namedtuple('ZipEOCD_', ('cur_disk', 'cd_disk', 'cd_count_local', 'cd_count_total', 'cd_sz', 'cd_offset', 'sz_comment', 'comment'))):
    signature = b'PK\x05\x06'
    length = 22

    @classmethod
    def parse(cls, hdr):
        if hdr[:4] != cls.signature:
            raise ValueError("Invalid signature")
        dt = struct.unpack("<HHHHLLH", hdr[4:22])
        comment = hdr[22:22+dt[6]]
        inst = cls(*dt, comment=comment)
        inst.length = 22 + dt[6]
        return inst

    def encode(self):
        return self.signature + struct.pack("<HHHHLLH", *self[:7]) + self.comment

def yieldEOCD(f):
    # Employing the freakin' root of all evil - TEH PREMATURE OPTIMIZATION!

    f.seek(0, 2) # To the EOF!

    p = f.tell() # file size
    dist = 0 # Current distance from end of file

    eocd_len, eocd_sig = ZipEOCD.length, ZipEOCD.signature
    if p < eocd_len:
        raise IOError("The zip file is too short.")

    # csz is - as its name suggests - the reading "chunk size".
    csz = eocd_len # First assume EOCD to be @ size - 22
    suffix = b'' 

    while p > 0:
        # Go back csz (chunk size) bytes
        p -= csz
        dist += csz
        f.seek(p, 0)

        chunk = f.read(csz)
        # [--- `dist` bytes ---] EOF
        # [chunk]
        # ^ current seek
        if len(chunk) != csz:
            # We went back and are reading forward, must be reading completely
            raise IOError("The zip flie has been concurrently modified.")

        eocd_i = len(chunk) # Start search from len(chunk) - 1 (Ignore signature @ len(chunk) - already processed in previous iteration from there); left direction (unintuitive, huh?)
        chunk += suffix # Add suffix (from previous read) to chunk
        while True:
            # by using eocd_i + len(pattern) - 1 we exclude the already checked (but dropped) signature of PK\x05\x06 at eocd_i.
            # We basically start searching from eocd_i - 1 (the 3rd parameter of str.rfind is "end" exclusive) from the right to the left.
	    # The behaviour of `end > len(chunk)` is well defined - check the doc if in doubt.
            eocd_i = chunk.rfind(eocd_sig, 0, eocd_i + len(eocd_sig) - 1)
            if eocd_i < 0:
                break
            elif eocd_i + 22 <= len(chunk): # This check exists to ensure that length of EOCD is at least 22.
                # Now we have found the signature
                # Check CommentLength <= dist - (eocd_i + 22)
                sz_comment = struct.unpack("<H", chunk[eocd_i+20:eocd_i+22])[0]
                if sz_comment <= dist - (eocd_i + eocd_len):
                    # Great!
                    yield p + eocd_i, ZipEOCD.parse(chunk[eocd_i:])
        suffix = chunk[:22+65535-1] # In case of .....P | K\x05\x06....
        csz = min(p - 0, 65536) # Chunk of random access

def relocate_zip(f, offset, suffix_len):
    assert 0 <= suffix_len <= 65535
    try:
        # XXX false positives?
        eocd_i, eocd = next(iter(yieldEOCD(f)))
    except StopIteration:
        raise IOError("Not a zip file") # No EOCD signature!
    if not (eocd.cur_disk == eocd.cd_disk == 0):
        raise IOError("Multi-volume archive is not supported.")
    
    new_comment, new_sz_comment = eocd.comment, eocd.sz_comment
    new_sz_comment += suffix_len # Has effect of ignoring suffix_len bytes
    if new_sz_comment > 65535:
        raise IOError("Comment too large")
    eocd_new_encoded = eocd._replace(cd_offset=eocd.cd_offset + offset, sz_comment=new_sz_comment, comment=new_comment).encode() # Relocate by offset
    f.seek(eocd_i, 0)
    f.write(eocd_new_encoded)

    cd_len = ZipCD.length
    i = eocd.cd_offset # Save original offset
    f.seek(i, 0)
    while True:
        hdr = f.read(46)
        if hdr[:4] == ZipEOCD.signature:
            break
        if hdr[:4] != ZipCD.signature:
            raise IOError("Invalid Central Directory signature: %s" % (repr(hdr[:4]),))
        cd = ZipCD.parse(hdr)
        cd_new_encoded = cd._replace(filename=f.read(cd.sz_filename),
            extra=f.read(cd.sz_extra),
            comment=f.read(cd.sz_comment),
            lf_offset=cd.lf_offset + offset).encode()
        assert len(cd_new_encoded) == cd.length
        f.seek(i, 0)
        f.write(cd_new_encoded)
        i += len(cd_new_encoded)

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 4:
        sys.stderr.write(("Usage: %s <filename> <offset> <suffix length>\n" % (sys.argv[0],)).encode())
        sys.exit(1)
    else:
        with open(sys.argv[1], "r+") as f:
            relocate_zip(f, int(sys.argv[2]), int(sys.argv[3]))
