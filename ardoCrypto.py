import binascii
import StringIO
import base64
from Crypto.Cipher import AES
from Crypto.Hash   import HMAC
from Crypto.Hash   import SHA256
from Crypto.Hash   import SHA512
from Crypto        import Random
from Crypto.Protocol.KDF import PBKDF2


# taken from somewhere
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
        if val > self.k:
            raise ValueError('Input is not padded or padding is corrupt')

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




def is_equal(a,b):
    if len(a) != len(b):
        return False

    result = 0
    for x,y in zip(a,b):
        result |= ord(x)^ord(y)

    return result == 0

padder = PKCS7Encoder()
salt = base64.b64decode('rgbah+AZtko0FlU0W6BCaaAuvKKlF2dAFHjrEVZTF+8RKQPOyn/RO9D8LOCLlAOxgoPad0HcQS5IAWYIq5RsMmihILUdWHe3Gr7YZJUNGtzPqZZI+VtmTS4Hvb+LHbahD5dhWey1moFlYmrxpjkisI1OPkS/1EnWaiaUf/9iVEw=')
random = Random.new()

# this is really slow in python :S
def deriveKey(password):
    return PBKDF2(password.encode('utf8'), salt, dkLen=32, count=37649, prf=None)

def kencrypt(key, plaintext):
    plaintext = plaintext.encode('utf8')
    iv = random.read(16)
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(padder.encode(plaintext))
    mac = HMAC.new(key, digestmod=SHA256)
    mac.update(iv)
    mac.update(ciphertext)
    return base64.b64encode(iv + ciphertext + mac.digest())


def kdecrypt(key, ciphertext):
    ciphertext = base64.b64decode(ciphertext)
    iv  = ciphertext[:16]
    mac_given = ciphertext[-32:]
    mac = HMAC.new(key, digestmod=SHA256)
    mac.update(ciphertext[0:-32])
    if not is_equal(mac_given,mac.digest()):
        raise Exception('decryption failed')
    plaintext = padder.decode(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext[16:-32]))
    return plaintext.decode('utf8')


def kdet_encrypt(key, plaintext):
    plaintext = plaintext.encode('utf8')
    mac = HMAC.new(key, digestmod=SHA256)
    mac.update(plaintext)
    iv = mac.digest()[:16]
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(padder.encode(plaintext))
    return base64.b64encode(iv + ciphertext)

def kdet_decrypt(key, ciphertext):
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:16]
    plaintext = padder.decode( AES.new(key, AES.MODE_CBC, iv).decrypt( ciphertext[16:] ) )
    if not is_equal(iv,HMAC.new(key, digestmod=SHA256, msg=plaintext).digest()[:16]):
        raise Exception('decryption failed')
    return plaintext.decode('utf8')


def encrypt(password, plaintext):
    return kencrypt(deriveKey(password), plaintext)

def decrypt(password, ciphertext):
    return kdecrypt(deriveKey(password), ciphertext)

def det_encrypt(password, plaintext):
    return kdet_encrypt(deriveKey(password), plaintext)

def det_decrypt(password, ciphertext):
    return kdet_decrypt(deriveKey(password), ciphertext)

def hash_password(password):
    salt = random.read(24)
    hash = SHA512.new()
    hash.update(salt)
    hash.update(password.encode('utf8'))
    return base64.b64encode(salt)+':'+base64.b64encode(hash.digest())

def compare_password(password, hash):
    split = hash.split(':')
    salt = base64.b64decode(split[0])
    new_hash = SHA512.new()
    new_hash.update(salt)
    new_hash.update(password.encode('utf8'))
    return is_equal(new_hash.digest(), base64.b64decode(split[1]))


if __name__=='__main__':
    import sys
    functions = { 
            'encrypt': encrypt, 
            'decrypt': decrypt, 
            'det_encrypt': det_encrypt, 
            'det_decrypt': det_decrypt
        }
    print functions[sys.argv[1]](sys.argv[2], sys.argv[3])

