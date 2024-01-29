from Crypto.Cipher import AES
from Crypto.Util.Padding import pad as pkcs7_pad, unpad as pkcs7_unpad
import argparse

def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx
    return zip(*[iter(iterable)]*n)

BYTE_ORDER:str = 'little'
LENGTH_PREFIX_BYTES:int = 4
BLOCK_SIZE:int = 16

KEY:bytes = b'qwertyuiQWERTYUI'

"""
BONUS:
A function to pad `source_str` with padding length so that the resulting byte string is a multiple of `block_size`
We will add a prefix of the message length to this padding.
"""
def pad(source_str:bytes, block_size:int = 16):
    assert block_size < 2**8, f"Block size {block_size} is NOT less than {2**8}"
    # First add the length of the source string as a 4 byte little endian number
    res = bytearray(len(source_str).to_bytes(
        LENGTH_PREFIX_BYTES, 
        byteorder=BYTE_ORDER,
    ))
    # Then, add the original source string
    res = res + bytearray(source_str)
    # Compute the padding element
    padding_length = block_size - len(res)%block_size
    print(padding_length)
    padding_element = padding_length.to_bytes(
        1, 
        byteorder=BYTE_ORDER,
    )
    padding_string = padding_element*padding_length
    res = res + padding_string
    return bytes(res)

"""
BONUS:
A function to remove the padding elements from `padded_string` so that the resulting string is unpadded

The function returns False if the padding is incorrect
"""
def unpad(padded_string:bytes, block_size:int = 16):
    source_string_length = int.from_bytes(
        padded_string[:LENGTH_PREFIX_BYTES],
        byteorder=BYTE_ORDER,
    )
    if (source_string_length + LENGTH_PREFIX_BYTES) % block_size == 0:
        return padded_string[LENGTH_PREFIX_BYTES:LENGTH_PREFIX_BYTES+source_string_length]
    padding_unit = 1

    # Check if the found padding matches the expected padding
    expected_padding = block_size - (source_string_length+LENGTH_PREFIX_BYTES)%block_size
    padding = int.from_bytes(
        padded_string[-padding_unit:],
        byteorder=BYTE_ORDER,
    )
    if padding != expected_padding:
        print(f"Mismatch: {expected_padding} {padding}")
        print(f"source length: {source_string_length}")
        print(f"Padding bytes: {padded_string[-4:]}")
        return False
    
    # Ensure all the padding elements are correct
    listed = list(padded_string)
    listed.reverse()
    grouped = list(grouper(listed, padding_unit))
    for element in grouped[:padding]:
        element = list(element)
        element.reverse()
        padding_element = int.from_bytes(
            element,
            byteorder=BYTE_ORDER,
        )
        if padding != padding_element:
            print("Padding mismatch")
            return False
    return padded_string[LENGTH_PREFIX_BYTES:LENGTH_PREFIX_BYTES + source_string_length]

"""
A function to encrypt a message `msg` using key `key` and IV `iv`
"""
def encrypt(plain_text:bytes, key:bytes, iv:bytes):
    padded_msg = pkcs7_pad(plain_text, BLOCK_SIZE)
    cryptor = AES.new(key, AES.MODE_CBC, iv)
    cipher = cryptor.encrypt(padded_msg)
    return cipher

"""
A function to decrypt the cipher `cipher` using the key `key` and IV `iv`
"""
def decrypt(cipher:bytes, key:bytes, iv:bytes):
    s = cipher
    decryptor = AES.new(key,AES.MODE_CBC,iv)
    plaintext = decryptor.decrypt(s) 
    return plaintext

"""
`oracle` returns whether the `cipher` contains the correct padding.
NOTE: This is the padding oracle function.
"""
def oracle(cipher:bytes, iv:bytes) -> bool:
    decrypted = decrypt(cipher, KEY, iv)
    try:
        pkcs7_unpad(decrypted, BLOCK_SIZE)
        return True
    except ValueError:
        return False

def attack(block):
    fake_iv = [0] * BLOCK_SIZE
    for padding_element in range(1, BLOCK_SIZE+1):
        padding_iv = [padding_element ^ b for b in fake_iv]
        for candidate in range(256):
            padding_iv[-padding_element] = candidate
            IV = bytes(padding_iv)
            if oracle(block, IV):
                if padding_element == 1:
                    padding_iv[-2] ^= 1
                    IV = bytes(padding_iv)
                    if not oracle(block, IV):
                        continue
                break
        else:
            raise Exception("Invalid Padding")
        fake_iv[-padding_element] = candidate ^ padding_element
    return fake_iv

"""
TODO: Demonstrate the padding oracle attack here!!!
"""
def padding_oracle_attack_exploit(ciphertext,iv):
    assert len(iv) == BLOCK_SIZE and len(ciphertext) % BLOCK_SIZE == 0
    message = iv + ciphertext
    blocks = [message[i:i+BLOCK_SIZE] for i in range(0, len(message), BLOCK_SIZE)]
    plaintext = b''
    IV = blocks[0]
    for ciphertext in blocks[1:]:
        intermediate_value = attack(ciphertext)
        temp = bytes(iv_byte ^ intermediate_byte for iv_byte, intermediate_byte in zip(IV, intermediate_value))
        plaintext += temp
        IV = ciphertext
    return pkcs7_unpad(plaintext, AES.block_size)


if __name__ == '__main__':
    iv = b'0000000000000000'
    # Test string
    p = b'This is cs528 padding oracle attack lab with hello world~~~!!'
    parser = argparse.ArgumentParser(description='Attack the oracle.')
    parser.add_argument("-p","--plaintext", dest="plaintext", help="plaintext in string format") #custom plaintext
    parser.add_argument("-i", "--iv", help="iv in string format (16-byte)") #custom IV
    args = parser.parse_args()

    if args.iv:
        iv = bytearray(args.iv, "UTF-8")
        print('Using iv: ' + str(iv))
    if args.plaintext:
        p = bytearray(args.plaintext, "UTF-8")
    
    ciphertext = encrypt(p,KEY,iv) #encrypt the plaintext
    plaintext = padding_oracle_attack_exploit(ciphertext,iv)
    print(f"Plaintext is : {bytes(plaintext).decode('utf-8')}")