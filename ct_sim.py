#!/usr/bin/python3
#
# Copyright (c) 2022-2025 Cisco and/or its affiliates.
#
# This software is licensed to you under the terms of the Cisco Sample
# Code License, Version 1.1 (the "License"). You may obtain a copy of the
# License at
#
#                https://developer.cisco.com/docs/licenses
#
# All use of the material herein must be in accordance with the terms of
# the License. All rights not expressly granted by the License are
# reserved. Unless required by applicable law or agreed to separately in
# writing, software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied.

import os
import sys
import base64
import binascii
import argparse
import zlib
import struct
import textwrap
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512


script_path = os.path.dirname(os.path.realpath(__file__))

"""
OpenSSL generated keyfile Name
"""
CT_DEMO_SIGNING_PRIKEY_FILE = script_path + "/ct_server_certs/ct_demo_signing_key.pem"

"""
CT Versions supported
"""
CT_VERSION_V6 = 0x106

"""
Function Codes supported
"""
CT_PRODUCT_FEATURE_CONFIG = 0x00000005

"""
Supported Function Code List
"""
CT_VERSION_V6_SUPPORTED_FUNCTION_CODES = [CT_PRODUCT_FEATURE_CONFIG]

"""
CT Specific defines
"""
CT_TYPE_FIELD_LENGTH = 1
CT_LENGTH_FIELD_LENGTH = 2
CT_TL_FIELD_LENGTH = (CT_TYPE_FIELD_LENGTH + CT_LENGTH_FIELD_LENGTH)
CT_CHECKSUM_LENGTH = 4
CT_VERSION_ID_LENGTH = 4
CT_FUNCTION_CODE_LENGTH = 4
CT_SUB_FUNCTION_CODE_LENGTH = 4
CT_NONCE_LENGTH = 8
CT_RANDOM_NUMBER_LENGTH = 16
CT_TTL_LENGTH = 4
CT_MAX_PROD_NAME_LENGTH = 64
CT_MAX_KEY_NAME_LENGTH = 64
CT_MAX_PID_LENGTH = 64
CT_MAX_SN_LENGTH = 64
CT_RSA_2048_KEY_LENGTH = 256
CT_RSA_2048_SIGNATURE_LENGTH = 256
CT_MAX_CHALLENGE_HEADER_LENGTH = 512
CT_MAX_CHALLENGE_LENGTH = (CT_RSA_2048_SIGNATURE_LENGTH * 8)
CT_MAX_RESPONSE_LENGTH = (CT_RSA_2048_SIGNATURE_LENGTH * 8)

"""
TLV
"""
#Common TLV-Type values
CT_TYPE_FUNCTION_CODE               = 0x01
CT_TYPE_SUB_FUNCTION_CODE           = 0x02

#Challenge TLV-Type values
CT_TYPE_NONCE                       = 0x03
CT_TYPE_RANDOM_NUMBER               = 0x04
CT_TYPE_TTL                         = 0x05
CT_TYPE_PROD_NAME                   = 0x06
CT_TYPE_KEY_NAME                    = 0x07
CT_TYPE_PID                         = 0x08
CT_TYPE_SN                          = 0x09

#Response TLV-Type values
CT_TYPE_SIGNATURE                   = 0x03

"""
SHA-512 OID values
"""
sha512_oid = "3051300D060960864801650304020305000440"


"""
Debug flags
"""
ENABLE_DEBUG = False
ENABLE_INFO = False


"""
ct_hexdump() prints the data in hex
"""
def ct_hexdump(data):
    spacing = " " * 6
    s = ":".join("{:02X}".format(c) for c in data)
    return spacing + '\n{}'.format(spacing).join(textwrap.wrap(s, 48))


"""
Adler32 Checksum computation
"""
def ct_compute_checksum(data):
    checksum = zlib.crc32(data) & 0xffffffff
    return checksum


"""
Verify Checksum
"""
def ct_verify_checksum(in_checksum, data):
    #print 'checksum input = {}'.format(data)
    computed_checksum = ct_compute_checksum(data)
    """
    if (in_checksum != computed_checksum):
        print 'ERROR: Checksum mismatch. Incoming checksum={} Computed checksum={}'.format(hex(in_checksum), hex(computed_checksum))
        return 0
    """

    return 1


"""
Generate pkcsv15 padded hash
"""
def generate_pkcsv15_padded_hash(in_hash):
    hash_val = binascii.unhexlify(in_hash)

    hash_oid_len = len(sha512_oid) // 2

    # "-3" is for initial \x00, \x01 and last \x00 padding byte
    padding_len = CT_RSA_2048_KEY_LENGTH - (len(hash_val) + 3 + hash_oid_len)

    oid = binascii.unhexlify(sha512_oid)
    pkcsv15_padded_hash = struct.pack("!BB{}sB{}s{}s".format(padding_len, len(oid), len(hash_val)), 0, 1, b'\xFF' * padding_len, 0, oid, hash_val)

    if ENABLE_DEBUG:
        print("PKCSv15 padded hash: {} \n".format(binascii.hexlify(pkcsv15_padded_hash)))

    return pkcsv15_padded_hash


"""
compute signature on entire challenge
"""
def ct_compute_signature(decoded_challenge):
    # Compute SHA-512 hash on the entire challenge
    challenge_hash = SHA512.new(decoded_challenge)

    # Read the OpenSSL-generated key file
    with open(CT_DEMO_SIGNING_PRIKEY_FILE, 'r') as f:
        ct_key = RSA.importKey(f.read())

    # Sign the hash using the private key and PKCS#1 v1.5
    signature = pkcs1_15.new(ct_key).sign(challenge_hash)

    return signature


"""
Challenge Class
"""
class CT_Challenge:
    """
    CT challenge initialization
    """
    def __init__(self):
        self.checksum               = 0
        self.version                = 0
        self.function_code          = 0
        self.sub_function_code      = 0
        self.nonce                  = 0
        self.random_number          = 0
        self.ttl                    = 0
        self.prod_name_length       = 0
        self.prod_name              = ''
        self.key_name_length        = 0
        self.key_name               = ''
        self.pid_length             = 0
        self.pid                    = ''
        self.sn_length              = 0
        self.sn                     = ''

    """
    Print Challenge Values
    """
    def __str__(self):
        # print public key info
        info = "\nCT Challenge Info :\n"
        info += "-----------------------\n"
        info += "Checksum                : {} \n".format(hex(self.checksum))
        info += "Version                 : {} \n".format(hex(self.version))
        info += "Function Code           : {} \n".format(hex(self.function_code))
        info += "Sub-Function Code       : {} \n".format(hex(self.sub_function_code))
        info += "Platform Nonce          : {} \n".format(self.nonce)
        info += "STO Nonce               : {} \n".format(self.random_number)
        info += "Time-to-live            : {} \n".format(self.ttl)
        info += "Product Name Length     : {} \n".format(self.prod_name_length)
        info += "Product Name            : {} \n".format(self.prod_name)
        info += "Key Name Length         : {} \n".format(self.key_name_length)
        info += "Key Name                : {} \n".format(self.key_name)
        info += "PID Length              : {} \n".format(self.pid_length)
        info += "PID                     : {} \n".format(self.pid)
        info += "SN Length               : {} \n".format(self.sn_length)
        info += "SN                      : {} \n".format(self.sn)
        return info

    """
    verify challenge info
    """
    def ct_verify_challenge_info(self, decoded_challenge):
        #print(self.function_code)
        #verify checksum
        if (ct_verify_checksum(self.checksum, binascii.hexlify(decoded_challenge[CT_CHECKSUM_LENGTH*2:])) == 0):
            return 0

        #verify version
        if (self.version < CT_VERSION_V6):
            print('ERROR: Invalid CT version')
            return 0

        if (self.function_code not in CT_VERSION_V6_SUPPORTED_FUNCTION_CODES[:]):
            print('ERROR: Invalid function code in V6 {}'.format(hex(self.function_code)))
            return 0

        return 1


    """
    Parse encoded challenge
    """
    def ct_parse_challenge(self, decoded_challenge):
        i = 0

        # checksum
        self.checksum = struct.unpack('!I', decoded_challenge[i:i+CT_CHECKSUM_LENGTH])[0]
        i += CT_CHECKSUM_LENGTH

        # version
        self.version = struct.unpack('!I', decoded_challenge[i:i+CT_VERSION_ID_LENGTH])[0]
        i += CT_VERSION_ID_LENGTH

        while decoded_challenge:
            try:
                t, l = struct.unpack('!BH', decoded_challenge[i:i+CT_TL_FIELD_LENGTH])
                i += CT_TL_FIELD_LENGTH

                # function code
                if (t == CT_TYPE_FUNCTION_CODE):
                    if (l != CT_FUNCTION_CODE_LENGTH):
                        print('ERROR: Invalid function code length')
                        return 0
                    self.function_code = struct.unpack('!I', decoded_challenge[i:i+l])[0]

                # sub-function code
                elif (t == CT_TYPE_SUB_FUNCTION_CODE):
                    if (l != CT_SUB_FUNCTION_CODE_LENGTH):
                        print('ERROR: Invalid sub function code length')
                        return 0
                    self.sub_function_code = struct.unpack('!I', decoded_challenge[i:i+l])[0]

                # platform nonce
                elif (t == CT_TYPE_NONCE):
                    if (l != CT_NONCE_LENGTH):
                        print('ERROR: Invalid nonce length')
                        return 0
                    self.nonce = binascii.hexlify(decoded_challenge[i:i+l]).decode()

                # sto nonce
                elif (t == CT_TYPE_RANDOM_NUMBER):
                    if (l != CT_RANDOM_NUMBER_LENGTH):
                        print('ERROR: Invalid random number length')
                        return 0
                    self.random_number = binascii.hexlify(decoded_challenge[i:i+l]).decode()

                # ttl
                elif (t == CT_TYPE_TTL):
                    if (l != CT_TTL_LENGTH):
                        print('ERROR: Invalid TTL length')
                        return 0
                    self.ttl = hex(struct.unpack('!I', decoded_challenge[i:i+l])[0])

                # product name
                elif (t == CT_TYPE_PROD_NAME):
                    if ((l == 0) or (l > CT_MAX_PROD_NAME_LENGTH)):
                        print('ERROR: Invalid Product Name length')
                        return 0
                    self.prod_name_length = l
                    self.prod_name = struct.unpack('!{}s'.format(l), decoded_challenge[i:i+l])[0].decode()

                # key name
                elif (t == CT_TYPE_KEY_NAME):
                    if ((l == 0) or (l > CT_MAX_KEY_NAME_LENGTH)):
                        print('ERROR: Invalid Key Name length')
                        return 0
                    self.key_name_length = l
                    self.key_name = struct.unpack('!{}s'.format(l), decoded_challenge[i:i+l])[0].decode()

                # pid
                elif (t == CT_TYPE_PID):
                    if ((l == 0) or (l > CT_MAX_PID_LENGTH)):
                        print('ERROR: Invalid PID length')
                        return 0
                    self.pid_length = l
                    self.pid = struct.unpack('!{}s'.format(l), decoded_challenge[i:i+l])[0].decode()

                # sn
                elif (t == CT_TYPE_SN):
                    if ((l == 0) or (l > CT_MAX_SN_LENGTH)):
                        print('ERROR: Invalid SN length')
                        return 0
                    self.sn_length = l
                    self.sn = struct.unpack('!{}s'.format(l), decoded_challenge[i:i+l])[0].decode()

                else:
                    pass

                i = i + l

            except:
                return 1


"""
Response Class
"""
class CT_Response:
    """
    CT Response initialization
    """
    def __init__(self):
        self.checksum                 = 0
        self.version                  = 0
        self.function_code            = 0
        self.sub_function_code        = 0
        self.signature                = 0


    """
    Print Challenge Values
    """
    def __str__(self):
        # print response info
        info = "\nCT Response Info :\n"
        info += "-----------------------\n"
        info += "Checksum                : {} \n".format(hex(self.checksum))
        info += "Version                 : {} \n".format(hex(self.version))
        info += "Function Code           : {} \n".format(hex(self.function_code))
        info += "Sub-Function Code       : {} \n".format(hex(self.sub_function_code))
        info += "CT Signature            : \n"
        info += ct_hexdump(self.signature) + "\n"
        return info


    """
    Compute final response
    """
    def ct_compute_response(self, args, version, function_code, sub_function_code, pid, sn, decoded_challenge):
        # populate response info
        self.version = version
        self.function_code = function_code
        self.sub_function_code = sub_function_code

        # function code tlv
        function_code_tlv = struct.pack('!BHI', CT_TYPE_FUNCTION_CODE,
                                        CT_FUNCTION_CODE_LENGTH, self.function_code)

        # sub-function code tlv
        sub_function_code_tlv = struct.pack('!BHI', CT_TYPE_SUB_FUNCTION_CODE,
                                            CT_SUB_FUNCTION_CODE_LENGTH, self.sub_function_code)

        # signature tlv
        # compute signature
        self.signature = ct_compute_signature(decoded_challenge)

        # base64 encode the challenge
        enc_signature = ''
        enc_signature = base64.b64encode(self.signature).decode()

        # split encoded signature across multiple lines, with max length of each line = 64
        loop = len(enc_signature) // 64 + (1 if len(enc_signature) % 64 else 0)

        encoded_signature = ''
        for i in range(loop):
            if i == loop:
                encoded_signature += enc_signature[i * 64:((i * 64) + 64)]
            else:
                encoded_signature += enc_signature[i * 64:((i * 64) + 64)] + '\n\r'

        if ENABLE_DEBUG:
            print('Encoded signature[{}] = {}'.format(len(encoded_signature), encoded_signature))

        signature_tlv = struct.pack('!BH{}s'.format(len(encoded_signature)),
                                    CT_TYPE_SIGNATURE, len(encoded_signature),
                                    encoded_signature.encode())

        # compute final response
        response = struct.pack('!I', self.version)
        response += function_code_tlv + sub_function_code_tlv + signature_tlv

        self.checksum = ct_compute_checksum(response)

        resp = struct.pack('!I', self.checksum) + response
        return resp


"""
ct_server_command_handler
"""
def ct_server_command_handler(args):
    global CT_DEMO_SIGNING_PRIKEY_FILE

    if args.logLevel == 'DEBUG':
        ENABLE_DEBUG = True
    elif args.logLevel == 'INFO':
        ENABLE_INFO = True

    # check the length of encoded challenge
    if (len(args.challenge) > CT_MAX_CHALLENGE_LENGTH):
        print('ERROR: Invalid encoded challenge length')
        return

    if args.private_key:
        CT_DEMO_SIGNING_PRIKEY_FILE = args.private_key

    # decode the incoming challenge
    decoded_challenge = base64.standard_b64decode(args.challenge)

    # challenge info
    ct_challenge = CT_Challenge()

    # parse incoming challenge info
    ct_challenge.ct_parse_challenge(decoded_challenge)

    # verify challenge info
    if ct_challenge.ct_verify_challenge_info(decoded_challenge) == 0:
        return

    # Response Info
    ct_response = CT_Response()

    # compute response
    response = ct_response.ct_compute_response(args, ct_challenge.version, ct_challenge.function_code,
                                                ct_challenge.sub_function_code, ct_challenge.pid, ct_challenge.sn,
                                                decoded_challenge)

    # base64 encode the response
    encoded_response = base64.b64encode(response).decode()

    # print encoded response
    print('\n-----------------------')
    print('Encoded Response :')
    print('-----------------------')
    print(encoded_response)
    print('\n')

    # if output filename is provided, save response to output file
    if args.out is not None:
        with open(args.out, 'wb') as f:
            f.write(encoded_response.encode())

        print('Response saved to {} file...'.format(args.out))

    return


"""
ct_arg_parser() is used to setup command line options.
"""
def ct_arg_parser():
    # setup main parser
    pmain = argparse.ArgumentParser()

    # Challenge
    pmain.add_argument("-C", "--challenge", metavar="<base64 encoded string>",
                       dest="challenge", help="Challenge string (Required)", required=True)

    # Output filename
    pmain.add_argument("-o", "--out", metavar="<response file>", dest="out",
                       required=False, help="Output signature file name.")

    # CT private key file
    pmain.add_argument("-p", "--private_key", metavar="<private key file>", dest="private_key",
                       required=False, help="Private key file (Optional). If not given, ct_server_certs/ct_demo_signing_key.pem will be used.")

    # Standard arguments
    pmain.add_argument("-logLevel", dest="logLevel", default="", required=False, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help="Logging level. Default: INFO")

    pmain.set_defaults(func=ct_server_command_handler)

    return pmain


"""
ct_server arg_parser() function
"""
def main():
    # main menu parser
    pmain = ct_arg_parser()

    # parse args
    args = pmain.parse_args()

    # invoke appropriate handler function
    status = args.func(args)

    return


"""
Starting point
"""
if __name__ == "__main__":
    sys.exit(main())