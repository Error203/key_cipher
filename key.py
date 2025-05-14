#!/usr/bin/python3
from Crypto.Cipher import Salsa20
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from sys import platform as current_platform
from hashlib import sha256
from collections import namedtuple
import argparse
import getpass
import os
import sys
import random
import qlogger
import string
import subprocess
import hmac

parser = argparse.ArgumentParser(description="program simply takes path to ciphered (with Salsa20) key, deciphers it, obfuscates and deltes the unciphered key")

parser.add_argument("-k", "--key", help="specify path to a ciphered key")
parser.add_argument("-o", "--output", help="set output file (or '-' for stdout)")

parser.add_argument("-c", "--cipher", help="crypt a key with a password", action="store_true")
parser.add_argument("-b", "--bytes", help="open a file in a bytes-reading form (not a plain text)", action="store_true")
parser.add_argument("-v", "--verbose", help="verbose, used for debugging in general", action="store_true")
parser.add_argument("-n", "--no-color", help="disable coloring (used for windows in general)", action="store_false")

arguments = parser.parse_args()

PATH = "~/keys/id_rsa.ciphered" if not arguments.key else arguments.key
PATH = os.path.expanduser(PATH)
ALPHABET = string.ascii_letters + string.digits
globdkLen = 32
# key deriviation length for PBKDF2
globiterations = 1_000_000
# iterations for the same reason
if arguments.output:
	arguments.output = os.path.expanduser(arguments.output)

# FUCKING MESS

# for debugging the code when its imported
# written this by mysels, thats why it so shit.
# OH MY FUCKING GOD ITS SO SHIT, but works for me.

# forget about it, fixed it, now it looks slim and nice. :)
if __name__ != "__main__":
	arguments.verbose = True

log = qlogger.Logger(level="debug" if arguments.verbose else "info", color=arguments.no_color).get_logger(os.path.basename(__file__))


def get_password(prompt="Password:"):
	try:
		passwd = bytes(getpass.getpass(prompt), "utf-8")

	except (KeyboardInterrupt, EOFError):
		log.info("interrupted by user")

		exit(1)

	except Exception as e:
		log.exception(e)

	return passwd

def confirm_password(password):
	return get_password("Repeat password:") == password

def is_bytes(value):
	return isinstance(value, bytes)

# === 	START KEY HANDLING 	===

class KeyHandlerPayload:

	# setting all to None to have an ability to get_key() without supplying extra info
	def __init__(self, data=None, password=None, nonce=None, salt=None):
		self.password = password
		self.dkLen = globdkLen
		self.iterations = globiterations
		self.nonce = nonce
		self.salt = salt
		self.data = data


		if not self.salt:
			log.debug("no salt, generating one")
			self.salt = os.urandom(16)

		if not self.nonce:
			log.debug("no nonce, generating one")
			self.nonce = os.urandom(8)

	# def _get_key_hmac(self):
	# 	self.key_hmac = PBKDF2(self.password, self.salt, dkLen=self.dkLen, count=self.iterations, hmac_hash_module=SHA256)

		# return self.key_hmac

	def _get_payload_hmac(self):
		self.payload = self.nonce + self.salt + self.data
		self.payload_hmac = hmac.new(self.key, self.payload, sha256).digest()

		return self.payload_hmac

	def _get_ready_payload(self):
		return self.payload + self.payload_hmac

	def get_key(self):
		self.key = PBKDF2(self.password, self.salt, dkLen=self.dkLen, count=self.iterations)
		log.debug("key generation ok")

		return self.key

	def get_payload(self):
		self._get_payload_hmac()

		return self._get_ready_payload()

class KeyHandlerVerify:

	def __init__(self, password, payload):
		self.password = password
		self.payload = payload
		self.dkLen = globdkLen
		self.iterations = globiterations
		self._get_fields()

	def _get_fields(self):
		self.nonce = self.payload[:8] # for nonce
		self.salt = self.payload[8:24] # for salt
		self.read_payload = self.payload[24:-32] # the actual payload
		self.payload_hmac = self.payload[-32:] # payload hmac

	def verify_payload(self):
		self.key_handler_payload = KeyHandlerPayload(
			nonce=self.nonce,
			data=self.read_payload, 
			password=self.password, 
			salt=self.salt
			)

		self.key = self.key_handler_payload.get_key()
		self.current_payload_hmac = self.key_handler_payload._get_payload_hmac()

		if not hmac.compare_digest(self.current_payload_hmac, self.payload_hmac):
			log.critical("wrong password or data is corrupted.")
			exit(1)

		else:
			log.debug("payload hash ok")

	# FUCKING AWFUL, I KNOW, BUT DONT REALLY CARE FOR NOW
	def get_key(self):
		self.key = PBKDF2(self.password, self.salt, dkLen=self.dkLen, count=self.iterations)
		log.debug("key generation ok")

		return self.key

# === 	END KEY HANDLING 	===

def handle_password(password, exit_on_failure=False):
	try:
		if not confirm_password(password):
			if exit_on_failure:
				log.critical("wrong password, program aborted")
				exit(1)

			log.error("wrong password")
			# maybe handle here Ctrl+D in the future, aka EOF key.

			while True:
				# repeating the cycle of getting a new password and confirming it
				password = get_password()
				if not confirm_password(password):
					log.error("wrong password")

				else:
					log.debug("password ok")
					break

	except (KeyboardInterrupt, EOFError):
		log.info("interrupted by user")

		exit(0)

	else:
		return password

def try_open(path_to_key, read_bytes=False):
	try:
		log.debug("bytes: " + str(arguments.bytes))
		mode = "r" if not arguments.bytes and arguments.cipher else "rb"
		log.debug("mode: " + mode)
		with open(path_to_key, mode) as file:
			data = bytes(file.read(), "utf-8") if mode == "r" else file.read()

	except UnicodeDecodeError:
		log.critical("file '%s' is bytes, can't decode, use -b for bytes" % path_to_key)
		exit(1)

	except OSError as error:
		log.error(error)

		exit(error.errno)

	except Exception as error:
		log.exception(error)

		exit(1)

	else:
		return data

def cipher(path_to_key, password):
	log.debug("ciphering '%s'" % path_to_key)

	password = handle_password(password, False)
	log.debug("password ok")

	key_unciphered = try_open(path_to_key)

	key_ciphered = None
	# it's the key that will be encrypted

	key_handler = KeyHandlerPayload(password=password)

	cipher = Salsa20.new(key=key_handler.get_key(), nonce=key_handler.nonce)
	key_ciphered = cipher.encrypt(key_unciphered)

	key_handler.data = key_ciphered
	# fucking ugly, but let it be.

	# no error checking, will do later
	path_to_ciphered_key = path_to_key + ".ciphered"

	encrypted_key = key_handler.get_payload()

	_path = path_to_ciphered_key
	
	if arguments.output:
		_path = arguments.output
		if _path == '-':
			sys.stdout.buffer.write(encrypted_key)

		else:
			write_key_to_file(_path, encrypted_key)

	log.info("successfully ciphered '%s' key: '%s'" % (path_to_key, _path))

def decipher(path_to_key, password):
	log.debug("deciphering '%s'" % path_to_key)
	
	key_ciphered = try_open(path_to_key, True)
	key_size = len(key_ciphered)

	# nonce = key_ciphered[:8]
	# key = key_ciphered[8:]

	key_verify = KeyHandlerVerify(password=password, payload=key_ciphered)
	key_verify.verify_payload()

	decipher = Salsa20.new(key=key_verify.get_key(), nonce=key_verify.nonce)

	key = key_verify.read_payload

	try:
		decrypted_key = decipher.decrypt(key).decode("utf-8") if not arguments.bytes else \
		decipher.decrypt(key)

	except UnicodeDecodeError as e:
		log.critical("failed to decode (maybe because of incorrect password), program aborted")
		# have to add a real checking for password
		if arguments.verbose:
			log.exception(e)

		exit(1)

	except Exception as e:
		log.exception(e)

	else:
		log.debug("password ok")

	if arguments.output:
		log.debug("output option: " + arguments.output)
		if arguments.output == '-':
			if not is_bytes(decrypted_key):
				sys.stdout.write(decrypted_key)

			else:
				sys.stdout.buffer.write(decrypted_key)
				# writing bytes

		else:
			log.warning("THE KEY WON'T BE AUTOMATICALLY CLEANED UP - keep that in mind")
			write_key_to_file(arguments.output, decrypted_key)

	else:
		key_path = obfuscate(decrypted_key)
		key_path_length = len(key_path)
		print("here is temporary path to a key, please press enter when you logged in:\n" + "=" * key_path_length)
		print(os.path.abspath(key_path) + "\n" + "=" * key_path_length)
		try:
			input()
		except (KeyboardInterrupt, EOFError):
			log.info("interrupted by user")
		except Exception as e:
			log.exception(e)
		finally:
			cleanup(key_path)

def write_key_to_file(path, key):
	# unlike obfuscate() func
	# this one doesnt delete the
	# file when done
	
	# shitty code by me:
	'''
	try:
		if arguments.bytes:
			file = open(path, "wb")

			if is_bytes(key):
				file.write(key)

			else:
				file.write(bytes(key, "utf-8"))
			
		else:
			file = open(path, "w")
			if is_bytes(key):
				file.write(key.decode("utf-8"))

			else:
				file.write(key)
	'''
	# normal code powered by chatgpt
	try:
		mode = "wb" if arguments.bytes or arguments.cipher else "w"

		with open(path, mode) as file:
			if arguments.bytes or arguments.cipher:
				file.write(key if is_bytes(key) else key.ecnode("utf-8"))
			else:
				file.write(key if not is_bytes(key) else key.decode("utf-8"))

	except OSError as e:
		log.error(e)

	except Exception as e:
		log.exception(e)


def obfuscate(key):
	name_length = random.randint(12, 28)
	name = ""
	for i in range(name_length):
		name += random.choice(ALPHABET)

	tmp_prefix = os.path.expandvars("$TMPDIR")
	# fix for termux, where there is a var named $TMPDIR, for normal distro use normal path
	
	if current_platform.startswith("win"):
		tmp_prefix = "."
		# handling windows, even though i doubt it'll work anyways on windows,
		# dont care to rewrite the whole code and troubleshoot it, maybe later.
	
	elif tmp_prefix == "$TMPDIR":
		tmp_prefix = "/tmp"


	path = os.path.join(tmp_prefix, name)

	log.debug("the path for the file is: '%s'" % path)

	try:

		write_key_to_file(path, key)

	except OSError as error:
		if error.errno == 13:
			# aka Permission Denied, for some reason?
			log.info("'%s': Permission denied, trying current directory" % path)
			with open(name, "w") as file:
				file.write(key)
		
		else:
			log.exception(error)
			exit(error.errno)

	except Exception as e:
		log.exception(e)

	# os.system("chmod 600 " + path)

	subprocess.run(["chmod", "600", path])
	# for some reason i think this will be more clear

	return path


def cleanup(key_path):
	if subprocess.run(["shred", key_path]).returncode:
		with open(key_path, "wb") as file:
			file.write(random.randbytes(key_size))

	os.remove(key_path)

	print("cleanup done!\n")


if __name__ == '__main__':
	if os.path.exists(PATH):
		password = get_password()

	else:
		log.info("'%s' not found, specify the key path via -k switch" % PATH)
		exit(1)

	if arguments.cipher:
		cipher(PATH, password)
	else:
		decipher(PATH, password)