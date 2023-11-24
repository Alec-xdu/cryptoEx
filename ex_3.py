import base64
from Crypto.Cipher import AES


def xor(str_1, str_2):
	return bytearray(s_1 ^ s_2 for s_1, s_2 in zip(str_1, str_2))


Key = 'YELLOW SUBMARINE'
iv = bytearray(b'\x00' * 16)
# print(iv)
plainText = AES.new(key=Key.encode(), mode=AES.MODE_ECB)
with open('10.txt', 'r') as baseFile:
	cipherText = base64.b64decode(baseFile.read().encode())
	# print(cipherText)
decrypt = ''
for i in range(0, len(cipherText), 16):
	plainStr = plainText.decrypt(cipherText[i:i+16])
	if i == 0:
		decrypt += str(xor(plainStr, iv).decode())
	else:
		decrypt += str(xor(plainStr, cipherText[i-16:i]).decode(errors='ignore'))
print(decrypt)
