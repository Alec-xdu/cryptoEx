import os
import base64
import random
from Crypto.Cipher import AES
from AES_CBC import *

b64_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
random_key = os.urandom(16)
random_string = os.urandom(random.randint(0, 255))


def AES128_harder(text: bytes) -> bytes:
	global b64_string, random_key, random_string

	secret_string = base64.b64decode(b64_string)
	plaintext = random_string + text + secret_string  # 随机前缀 + 攻击者控制 + 目标字节
	cipher = AES_ECB_encrypt(plaintext, random_key)
	return cipher


def break_AES_ECB_harder(keysize: int, encryptor: callable) -> bytes:
	# 寻找前缀长度
	padding = 0
	random_blocks = 0
	cipher_length = len(encryptor(b''))
	prefix_length = len(os.path.commonprefix([encryptor(b'AAAA'), encryptor(b'')]))
	print("Prefix length: ", prefix_length)

	# 查找随机块的数量
	for i in range(int(cipher_length / keysize)):
		if prefix_length < i * keysize:
			random_blocks = i
			break
	print("Random blocks: ", random_blocks)

	# 查找所需的字节填充数
	base_cipher = encryptor(b'')
	for i in range(1, keysize):
		new_cipher = encryptor(b'A' * i)
		new_prefix_length = len(os.path.commonprefix([base_cipher, new_cipher]))
		if new_prefix_length > prefix_length:
			padding = i - 1
			break
		base_cipher = new_cipher
	print("Number of bytes of padding required: ", padding)

	deciphered = b""
	ciphertext = encryptor(deciphered)
	# 添加了填充，增加了一个块
	run = len(ciphertext) + keysize

	for i in range(keysize * random_blocks + 1, run + 1):
		template = b'A' * (run - i + padding)
		cipher = encryptor(template)
		for j in range(256):
			# print(i, j)
			text = template + deciphered + j.to_bytes(1, "little")
			c = encryptor(text)
			if c[run - keysize:run] == cipher[run - keysize:run]:
				deciphered += chr(j).encode()
				break
	return PKCS7_unpad(deciphered)


keysize = 16
byte_text = break_AES_ECB_harder(keysize, AES128_harder)
print("\nDeciphered string:\n")
print(byte_text.decode("utf-8").strip())