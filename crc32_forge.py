#!/usr/bin/env python2

## Borrows code from
"""Calculate and manipulate CRC32.
http://en.wikipedia.org/wiki/Cyclic_redundancy_check
-- StalkR
"""
## See https://github.com/StalkR/misc/blob/master/crypto/crc32.py

import struct
import sys
import os

class CRC32(object):
  """A class to calculate and manipulate CRC32.
"""
  def __init__(self):
    self.polynom = 0x82F63B78
    self.table, self.reverse = [0]*256, [0]*256
    self._build_tables()

  def _build_tables(self):
    for i in range(256):
      fwd = i
      rev = i << 24
      for j in range(8, 0, -1):
        # build normal table
        if (fwd & 1) == 1:
          fwd = (fwd >> 1) ^ self.polynom
        else:
          fwd >>= 1
        self.table[i] = fwd & 0xffffffff
        # build reverse table =)
        if rev & 0x80000000 == 0x80000000:
          rev = ((rev ^ self.polynom) << 1) | 1
        else:
          rev <<= 1
        rev &= 0xffffffff
        self.reverse[i] = rev

  def calc(self, s):
    """Calculate crc32 of a string.
       Same crc32 as in (binascii.crc32)&0xffffffff.
    """
    crc = 0xffffffff
    for c in s:
      crc = (crc >> 8) ^ self.table[(crc ^ ord(c)) & 0xff]
    return crc^0xffffffff

  def forge(self, wanted_crc, s, pos=None):
    """Forge crc32 of a string by adding 4 bytes at position pos."""
    if pos is None:
      pos = len(s)

    # forward calculation of CRC up to pos, sets current forward CRC state
    fwd_crc = 0xffffffff
    for c in s[:pos]:
      fwd_crc = (fwd_crc >> 8) ^ self.table[(fwd_crc ^ ord(c)) & 0xff]

    # backward calculation of CRC up to pos, sets wanted backward CRC state
    bkd_crc = wanted_crc^0xffffffff
    for c in s[pos:][::-1]:
      bkd_crc = ((bkd_crc << 8)&0xffffffff) ^ self.reverse[bkd_crc >> 24] ^ ord(c)

    # deduce the 4 bytes we need to insert
    for c in struct.pack('<L',fwd_crc)[::-1]:
      bkd_crc = ((bkd_crc << 8)&0xffffffff) ^ self.reverse[bkd_crc >> 24] ^ ord(c)

    res = s[:pos] + struct.pack('<L', bkd_crc) + s[pos:]
    return res

if __name__=='__main__':

    crc = CRC32()
    wanted_crc = 0x00000000
    count = 0
    while count < 512:
        origname = os.urandom (10).encode ("hex").strip ("\x00")
        forgename = crc.forge(wanted_crc, origname, 4)
        if ("/" not in forgename) and ("\x00" not in forgename):
            file (str(count), 'a').close()
            os.rename(str(count), forgename)
            os.system('btrfs fi sync .')
            count+=1;

