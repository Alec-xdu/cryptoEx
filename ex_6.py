import random

from Crypto.Cipher import AES


def PKCS7Padding(pad):
	block = 16
	padding = pad
	padLen = len(padding)
	lastLoc = block - padLen % block
	salt = '{:x}'.format(lastLoc)
	if lastLoc != block:
		for i in range(0, lastLoc):
			padding += salt
	# print(padding)
	return padding


def generateRandomKey(length: int) -> hex:
	key = ''
	for i in range(0, length):
		key += hex(random.randint(0, 255))[2:]
	return hex(int(key, 16))[:16]


# 将参数格式化
def urlEncode(dict_param: dict) -> str:
	text = ''
	for subItem in dict_param.items():
		text += (subItem[0] + '=' + str(subItem[1]) + '&')
	return text[:-1]


class ECBOracle:
	def __init__(self):
		self.__key = generateRandomKey(AES.key_size[0])

	def encrypt(self, email: str):
		encode = PKCS7Padding(urlEncode(profile(email)))
		encode = encode.encode()
		return AES.new(mode=AES.MODE_ECB, key=self.__key.encode()).encrypt(encode)

	def decrypt(self, cipherText: str):
		return AES.new(mode=AES.MODE_ECB, key=self.__key.encode()).decrypt(cipherText)


def parse(text: str):
	dict_ = {}
	attributes = text.split('&')
	for attribute in attributes:
		values = attribute.split('=')
		key = int(values[0]) if values[0].isdigit() else values[0]
		value = int(values[1]) if values[1].isdigit() else values[1]
		dict_[key] = value
	# print(dict_)
	return dict_


def cutAndPaste(oracle: ECBOracle):
	prefixLen = AES.block_size - 6
	suffixLen = AES.block_size - 5
	email = 'x' * prefixLen + 'admin' + (chr(suffixLen) * suffixLen)
	encryption = oracle.encrypt(email)
	anotherEmail = 'hello1@qq.com'
	encryption2 = oracle.encrypt(anotherEmail)
	result = encryption2[:32] + encryption[16:32]
	return result


def profile(email: str):
	email = email.replace('&', '').replace('=', '')
	return {'email': email, 'uid': 10, 'role': 'user'}


if __name__ == '__main__':
	oracle = ECBOracle()
	ciperText = cutAndPaste(oracle)
	decrypted = oracle.decrypt(ciperText)
	parsed = parse(decrypted.decode())
	print(parsed)
