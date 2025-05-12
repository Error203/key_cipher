#!/usr/bin/python3
from Crypto.Cipher import Salsa20
from Crypto.Util.Padding import pad
from sys import platform as current_platform
import argparse
import getpass
import os
import random
import qlogger
import string
import subprocess

parser = argparse.ArgumentParser(description="program simply takes path to ciphered (with Salsa20) key, deciphers it, obfuscates and deltes the unciphered key")

parser.add_argument("-k", "--key", help="specify path to a ciphered key")

parser.add_argument("-c", "--cipher", help="crypt a key with a password", action="store_true")
parser.add_argument("-b", "--bytes", help="open a file in a bytes-reading form (not a plain text)", action="store_true")
parser.add_argument("-v", "--verbose", help="verbose, used for debugging in general", action="store_true")
parser.add_argument("-n", "--no-color", help="disable coloring (used for windows in general)", action="store_false")

arguments = parser.parse_args()

PATH = "~/keys/id_rsa.ciphered" if not arguments.key else arguments.key
PATH = os.path.expanduser(PATH)
ALPHABET = string.ascii_letters + string.digits

log = qlogger.Logger(level="debug" if arguments.verbose else "info", color=arguments.no_color).get_logger(os.path.basename(__file__))

# maybe not that safe? i mean converting it to bytes

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
		with open(path_to_key, "r" if not arguments.bytes and not read_bytes else "rb") as file:
			data = bytes(file.read(), "utf-8") if not arguments.bytes and not read_bytes else file.read()

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

	cipher = Salsa20.new(key=pad(password, 16))
	nonce = cipher.nonce
	key_ciphered = nonce + cipher.encrypt(key_unciphered)

	# no error checking, will do later
	path_to_ciphered_key = path_to_key + ".ciphered"
	with open(path_to_ciphered_key, "wb") as file:
		file.write(key_ciphered)

	log.info("successfully ciphered '%s' key: '%s'" % (path_to_key, path_to_ciphered_key))

def decipher(path_to_key, password):
	log.debug("deciphering '%s'" % path_to_key)
	
	key_ciphered = try_open(path_to_key, True)

	nonce = key_ciphered[:8]
	key = key_ciphered[8:]
	decipher = Salsa20.new(pad(password, 16), nonce)
	try:
		decrypted_key = decipher.decrypt(key).decode("utf-8")

	except UnicodeDecodeError:
		log.critical("wrong password, program aborted")
		exit(1)

	except Exception as e:
		log.exception(e)

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

		with open(path, "w") as file:
			file.write(key)

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
		log.exception(error)

	# os.system("chmod 600 " + path)

	subprocess.run(["chmod", "600", path])
	# for some reason i think this will be more clear

	return path


def cleanup(key_path):
	if os.system("shred " + key_path):
		with open(key_path, "w") as file:
			file.write(random.randbytes(5000))

	os.remove(key_path)

	print("cleanup done!\n")


if __name__ == '__main__':
	password = get_password()

	if arguments.cipher:
		cipher(PATH, password)
	else:
		decipher(PATH, password)