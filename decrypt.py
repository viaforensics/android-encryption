#!/usr/bin/env python
#
# Android FDE Decryption
#
# Authors:  Thomas Cannon <tcannon@viaforensics.com>
#           Andrey Belenko <abelenko@viaforensics.com>
# Requires: Python, M2Crypto (sudo apt-get install python-m2crypto)
#
# Parses the header for the encrypted userdata partition.
# Decrypts the master key found in the header using a supplied password
# Decrypts the first sector of an encrypted userdata partition using the decrypted key
# Written for Nexus S (crespo) running Android 4.0.4
# Header is located in file userdata_footer on the efs partition

# Imports
from os import path
from M2Crypto import EVP
import hashlib
import struct

# Inputs
header_file = "userdata_footer_1234"
encrypted_partition = "userdata_encrypted.dd"
password = "1234"

# Constants
HEADER_FORMAT = "=LHHLLLLLLL64s"  # Taken from cryptfs.h in crespo source.
HASH_COUNT = 2000
KEY_LEN_BYTES = 16
IV_LEN_BYTES = 16
SECTOR_SIZE = 512
BLOCK_SIZE = 16
SECTOR_OFFSET = 0
ENCRYPT = 1
DECRYPT = 0

# Check input files exist then read the header file
assert path.isfile(header_file), "Input file '%s' not found." % header_file
assert path.isfile(encrypted_partition), "Input file '%s' not found." % encrypted_partition
header = open(header_file, 'rb').read()

# Unpack header
ftrMagic, \
majorVersion, \
minorVersion, \
ftrSize, \
flags, \
keySize, \
spare1, \
fsSize1, \
fsSize2, \
failedDecrypt, \
cryptoType = \
struct.unpack(HEADER_FORMAT, header[0:100])

encrypted_key = header[ftrSize:ftrSize + keySize]
salt = header[ftrSize + keySize + 32:ftrSize + keySize + 32 + 16]

# Display parsed header
print 'Magic          :', "0x%0.8X" % ftrMagic
print 'Major Version  :', majorVersion
print 'Minor Version  :', minorVersion
print 'Footer Size    :', ftrSize, "bytes"
print 'Flags          :', "0x%0.8X" % flags
print 'Key Size       :', keySize * 8, "bits"
print 'Failed Decrypts:', failedDecrypt
print 'Crypto Type    :', cryptoType.rstrip("\0")
print 'Encrypted Key  :', "0x" + encrypted_key.encode("hex").upper()
print 'Salt           :', "0x" + salt.encode("hex").upper()
print '----------------'

# Calculate the key decryption key and IV from the password
pbkdf2 = EVP.pbkdf2(password, salt, iter=HASH_COUNT, keylen=KEY_LEN_BYTES + IV_LEN_BYTES)
key = pbkdf2[:KEY_LEN_BYTES]
iv = pbkdf2[KEY_LEN_BYTES:]

# Decrypt the encryption key
cipher = EVP.Cipher(alg='aes_128_cbc', key=key, iv=iv, padding=0, op=DECRYPT)
decrypted_key = cipher.update(encrypted_key)
decrypted_key = decrypted_key + cipher.final()

# Display the decrypted key
print 'Password       :', password
print 'Derived Key    :', "0x" + key.encode("hex").upper()
print 'Derived IV     :', "0x" + iv.encode("hex").upper()
print 'Decrypted Key  :', "0x" + decrypted_key.encode("hex").upper()
print '----------------'

# Calculate ESSIV
# ESSIV mode is defined by:
# SALT=Hash(KEY)
# IV=E(SALT,sector_number)
salt = hashlib.sha256(decrypted_key).digest()
sector_number = struct.pack("<I", SECTOR_OFFSET) + "\x00" * (BLOCK_SIZE - 4)

# Since our ESSIV hash is SHA-256 we should use AES-256
# We use ECB mode here (instead of CBC with IV of all zeroes) due to crypto lib weirdness
# EVP engine PKCS7-pads data by default so we explicitly disable that
cipher = EVP.Cipher(alg='aes_256_ecb', key=salt, iv='', padding=0, op=ENCRYPT)
essiv = cipher.update(sector_number)
essiv += cipher.final()

print 'SECTOR NUMBER  :', "0x" + sector_number.encode("hex").upper()
print 'ESSIV SALT     :', "0x" + salt.encode("hex").upper()
print 'ESSIV IV       :', "0x" + essiv.encode("hex").upper()
print '----------------'

# Decrypt first sector of userdata image
encrypted_data = open(encrypted_partition, 'rb').read(SECTOR_SIZE)
cipher = EVP.Cipher(alg='aes_128_cbc', key=decrypted_key, iv=essiv, padding=0, op=DECRYPT)
decrypted_data = cipher.update(encrypted_data)
decrypted_data = decrypted_data + cipher.final()

# Print the decrypted data
print 'Decrypted Data :', "0x" + decrypted_data.encode("hex").upper()

