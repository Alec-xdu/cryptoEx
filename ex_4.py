import binascii

from Crypto.Cipher import AES
import random

from conda_build.build import chunks


def PKCS7Padding(pad):
	block = 16
	padding = pad
	padLen = len(padding)
	lastLoc = block - padLen % block
	salt = '{:x}'.format(lastLoc)
	if lastLoc != block:
		for i in range(0, lastLoc):
			padding += salt
	print(padding)
	return padding


# 生成随机的AES密钥
def generateRandomKey(length: int) -> hex:
	key = ''
	for i in range(0, length):
		key += hex(random.randint(0, 255))[2:]
	return hex(int(key, 16))[:16]


def randEncrypt(key, iv, iStr):
	flag = random.randint(1, 2)
	preRandom = generateRandomKey(random.randint(5, 10))
	nexRandom = generateRandomKey(random.randint(5, 10))
	plainStr = PKCS7Padding(preRandom + iStr + nexRandom)
	print(flag)
	if flag == 1:
		cipher = AES.new(key=key.encode(), mode=AES.MODE_ECB).encrypt(plainStr)
		print('AES ECB encrypting...')
	else:
		cipher = AES.new(key=key.encode(), mode=AES.MODE_CBC, IV=iv.encode()).encrypt(plainStr)
		print('AES CBC encrypting...')
	return cipher


def detect_mode(ciphertext):
	blocks = [b for b in chunks(ciphertext, 16)]
	detects = []
	for b in blocks:
		if blocks.count(b) > 1:
			detects.append(b)
	if detects:
		print("ECB MODE detected!")


string = 'I come to the playground and play with my friends, what a nice day i thought'
cipherText = str(randEncrypt(key=generateRandomKey(16), iv=generateRandomKey(16), iStr=string))
detect_mode(cipherText)
print(cipherText)
