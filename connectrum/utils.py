#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# copied from code https://github.com/spesmilo/electrum
# Used to convert address to scripthash

import binascii
import hashlib
from typing import Tuple, Optional, Union
from .constants import ADDRTYPE_P2PKH, ADDRTYPE_P2SH, ADDRTYPE_P2SH_ALT, SEGWIT_HRP
from . import segwit_addr

bfh = bytes.fromhex
hfu = binascii.hexlify

__b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(__b58chars) == 58

__b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
assert len(__b43chars) == 43

def bh2u(x: bytes) -> str:
    """
    str with hex representation of a bytes-like object

    >>> x = bytes((1, 2, 10))
    >>> bh2u(x)
    '01020A'
    """
    return hfu(x).decode('ascii')

def sha256(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, 'utf8')
    return bytes(hashlib.sha256(x).digest())

def rev_hex(s: str) -> str:
    return bh2u(bfh(s)[::-1])

def int_to_hex(i: int, length: int=1) -> str:
    """Converts int to little-endian hex string.
    `length` is the number of bytes available
    """
    if not isinstance(i, int):
        raise TypeError('{} instead of int'.format(i))
    range_size = pow(256, length)
    if i < -(range_size//2) or i >= range_size:
        raise OverflowError('cannot convert int {} to hex ({} bytes)'.format(i, length))
    if i < 0:
        # two's complement
        i = range_size + i
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return rev_hex(s)

def op_push(i: int) -> str:
    if i<0x4c:  # OP_PUSHDATA1
        return int_to_hex(i)
    elif i<=0xff:
        return '4c' + int_to_hex(i)
    elif i<=0xffff:
        return '4d' + int_to_hex(i,2)
    else:
        return '4e' + int_to_hex(i,4)

def push_script(data: str) -> str:
    """Returns pushed data to the script, automatically
    choosing canonical opcodes depending on the length of the data.
    hex -> hex

    ported from https://github.com/btcsuite/btcd/blob/fdc2bc867bda6b351191b5872d2da8270df00d13/txscript/scriptbuilder.go#L128
    """
    data = bfh(data)
    from .opcode import opcodes

    data_len = len(data)

    # "small integer" opcodes
    if data_len == 0 or data_len == 1 and data[0] == 0:
        return bh2u(bytes([opcodes.OP_0]))
    elif data_len == 1 and data[0] <= 16:
        return bh2u(bytes([opcodes.OP_1 - 1 + data[0]]))
    elif data_len == 1 and data[0] == 0x81:
        return bh2u(bytes([opcodes.OP_1NEGATE]))

    return op_push(data_len) + bh2u(data)

def address_to_script(addr: str) -> str:
    witver, witprog = segwit_addr.decode(SEGWIT_HRP, addr)
    if witprog is not None:
        if not (0 <= witver <= 16):
            raise logger.exception('impossible witness version: {witver}')
        OP_n = witver + 0x50 if witver > 0 else 0
        script = bh2u(bytes([OP_n]))
        script += push_script(bh2u(bytes(witprog)))
        return script
    addrtype, hash_160_ = b58_address_to_hash160(addr)
    if addrtype == ADDRTYPE_P2PKH:
        script = '76a9'                                      # op_dup, op_hash_160
        script += push_script(bh2u(hash_160_))
        script += '88ac'                                     # op_equalverify, op_checksig
    elif addrtype in [ADDRTYPE_P2SH, ADDRTYPE_P2SH_ALT]:
        script = 'a9'                                        # op_hash_160
        script += push_script(bh2u(hash_160_))
        script += '87'                                       # op_equal
    else:
        raise logger.exception('unknown address type: {addrtype}')
    return script

def address_to_scripthash(addr: str) -> str:
    script = address_to_script(addr)
    return script_to_scripthash(script)

def script_to_scripthash(script: str) -> str:
    h = sha256(bfh(script))[0:32]
    return bh2u(bytes(reversed(h)))

def base_decode(v: Union[bytes, str], length: Optional[int], base: int) -> Optional[bytes]:
    """ decode v into a string of len bytes."""
    # assert_bytes(v)
    v = to_bytes(v, 'ascii')
    if base not in (58, 43):
        raise ValueError('not supported base: {}'.format(base))
    chars = __b58chars
    if base == 43:
        chars = __b43chars
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        digit = chars.find(bytes([c]))
        if digit == -1:
            raise ValueError('Forbidden character {} for base {}'.format(c, base))
        long_value += digit * (base**i)
    result = bytearray()
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result.append(mod)
        long_value = div
    result.append(long_value)
    nPad = 0
    for c in v:
        if c == chars[0]:
            nPad += 1
        else:
            break
    result.extend(b'\x00' * nPad)
    if length is not None and len(result) != length:
        return None
    result.reverse()
    return bytes(result)

def b58_address_to_hash160(addr: str) -> Tuple[int, bytes]:
    addr = to_bytes(addr, 'ascii')
    _bytes = base_decode(addr, 25, base=58)
    return _bytes[0], _bytes[1:21]

def to_bytes(something, encoding='utf8') -> bytes:
    """
    cast string to bytes() like object, but for python2 support it's bytearray copy
    """
    if isinstance(something, bytes):
        return something
    if isinstance(something, str):
        return something.encode(encoding)
    elif isinstance(something, bytearray):
        return bytes(something)
    else:
        raise TypeError("Not a string or bytes like object")
