#!/usr/bin/python3
# fucking mess, but works for me.
# script for testing things, duh

import sys
import os

sys.path.append(os.path.abspath(__file__))
sys.path.append(os.path.abspath("."))

import key as key_module

def main():
	data = b"some payload"
	password = b"password123"
	nonce = b"\x10\x20\x30\x40\x50\x60\x70\x80"
	handler = key_module.KeyHandlerPayload(data, password, nonce)
	key = handler.get_key() # the actual key, got from SALT and PASSWORD
	payload_hmac = handler._get_payload_hmac() # hmac of payload at the end of the file
	complete_payload = handler.get_payload() # payload i get by reading a file

	print("key:", key.hex())
	print("payload_hmac:", payload_hmac)
	print("complete_payload:", complete_payload)

	verify = key_module.KeyHandlerVerify(password, complete_payload)
	verify.verify_payload()

if __name__ == '__main__':
	main()
