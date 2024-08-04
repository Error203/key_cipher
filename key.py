from Crypto.Cipher import Salsa20
from Crypto.Util.Padding import pad
import argparse
import getpass
import os
import random

parser = argparse.ArgumentParser(description="program simply takes path to ciphered (with Salsa20) key, deciphers it, obfuscates and deltes the unciphered key")

parser.add_argument("-k", "--key", help="path to ciphered key")
parser.add_argument("-c", "--cipher", help="turn on switch to cipher", action="store_true")

arguments = parser.parse_args()

PATH = "~/keys/id_rsa.ciphered" if not arguments.key else arguments.key
ALPHABET = "abcdefghijklmnopqrstuvwxyz"
ALPHABET = ALPHABET + ALPHABET.upper() + "0123456789"

password = pad(bytes(getpass.getpass(), "utf-8"), 16)

def cipher(path_to_key, password):
	with open(path_to_key, "r") as file:
		key_unciphered = bytes(file.read(), "utf-8")

	key_ciphered = None
	password = bytes(password, "utf-8")
	cipher = Salsa20.new(key=password)
	nonce = cipher.nonce
	key_ciphered = nonce + cipher.encrypt(key_unciphered)

	with open(path_to_key + ".ciphered", "wb") as file:
		file.write(key_ciphered)


def decipher(path_to_key, password):
	with open(path_to_key, "rb") as file:
		key_ciphered = file.read()

	nonce = key_ciphered[:8]
	key = key_ciphered[8:]
	decipher = Salsa20.new(password, nonce)
	key_path = obfuscate(decipher.decrypt(key).decode("utf-8"))
	print("here is temporary path to a key, please press enter when you logged in:\n" + "=" * 20)
	print(key_path + "\n" + "=" * 20)
	try:
		input()
	except Exception:
		pass
	finally:
		cleanup(key_path)


def obfuscate(key):
	name_length = random.randint(12, 28)
	name = ""
	for i in range(name_length):
		name += random.choice(ALPHABET)

	path = "/tmp/" + name

	with open(path, "w") as file:
		file.write(key)

	os.system("chmod 600 " + path)

	return path


def cleanup(key_path):
	if os.system("shred " + key_path):
		with open(key_path, "w") as file:
			file.write(random.randbytes(5000))

	os.remove(key_path)

	print("cleanup done!\n")


if __name__ == '__main__':
	if arguments.cipher:
		cipher(PATH, password)
	else:
		decipher(PATH, password)