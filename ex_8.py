import base64
import Crypto.Random
import Crypto.Random.random
from Crypto.Cipher import AES


def xor_byte_strings(input_bytes_1, input_bytes_2):
	return bytes([x ^ y for x, y in zip(input_bytes_1, input_bytes_2)])


def pkcs7_pad(data, block_size):
	# get the size of padding
	padding_size = block_size - len(data) % block_size
	if padding_size == 0:
		padding_size = block_size
	# add it
	padding = (chr(padding_size) * padding_size).encode()
	return data + padding


def AES_ECB_encode(plaintext_b, key_b):
	cipher = AES.new(key_b, AES.MODE_ECB)
	ciphertext = cipher.encrypt(plaintext_b)
	return ciphertext


# returns a sepecified lenth of random bytes
def generate_random_key(key_length):
	return Crypto.Random.get_random_bytes(key_length)


def determine_block_size():
	"""Determines the block size of encryption by continuously
	appending and encrypting data and measuring the size of the
	output.
	"""
	data = b''
	initial_length = len(encryption_oracle(data))
	while True:
		# 明文长度每次增加1
		data += b'A'
		result_length = len(encryption_oracle(data))
		# 当密文长度发生变化时,中断
		if result_length != initial_length:
			break
	# 两次密文长度差,就是block_size
	block_size = result_length - initial_length
	need_prefix_padding_size = len(data)
	return block_size


# 加密函数：每次都会在data前面添上一个随机数，后面附上一段话,再用AES的ECB模式进行加密
# 目标：获取附加内容
def encryption_oracle(data):
	unknown_string = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''
	suffix = base64.b64decode(unknown_string.encode())
	data_to_encrypt = pkcs7_pad(random_prefix + data + suffix, block_size)
	ciphertext = AES_ECB_encode(data_to_encrypt, key)
	return ciphertext


def count_the_same_length(bytes1, bytes2):
	count = 0
	xor = xor_byte_strings(bytes1, bytes2)
	for i in xor:
		if i == 0:
			count += 1
		else:
			break
	return count


def determine_prefix_padding_size(block_size):
	data = b''
	cipher_of_pre = encryption_oracle(data)

	data += b'A'
	init_block_num = count_the_same_length(cipher_of_pre, encryption_oracle(data)) // block_size
	while (True):
		data += b'A'
		cipher_of_A = encryption_oracle(data)
		same_block_num = count_the_same_length(cipher_of_pre, cipher_of_A) // block_size
		if same_block_num != init_block_num:
			break
		else:
			cipher_of_pre = cipher_of_A
	return same_block_num * block_size - len(data) + 1


def decrypt_byte(block_size, prefix_padding_size, decrypted_message):
	"""Decrypts a ciphertext one byte at a time by continuosly encrypting a message and comparing the ciphertext.
	"""
	# 我们需要把探针+1的长度
	# s.t. 探针+1+前缀长度 向assume_block_size补齐
	# 这里的1即：byte combinations
	probe_length = block_size - ((1 + len(decrypted_message) + prefix_padding_size) % block_size)

	# s.t. 总体长度为assume_block_size的整数倍
	testing_length = prefix_padding_size + probe_length + (len(decrypted_message) + 1)

	# A dictionary of every possible last byte from encrypting
	# different probe + decrypted_message + byte combinations
	# probes for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC"
	byte_dict = {}
	for byte in range(256):
		test_data = b"A" * (probe_length) + decrypted_message + bytes([byte])
		test_ciphertext = encryption_oracle(test_data)
		byte_dict[test_ciphertext[:testing_length]] = byte
	comparison_ciphertext = encryption_oracle(b"A" * (probe_length))[:testing_length]
	plaintext = bytes([byte_dict.get(comparison_ciphertext, 0)])
	return plaintext


def main():
	# Determine the block size.
	# is assumed to be equal to block_size.
	assume_block_size = determine_block_size()
	prefix_padding_size = determine_prefix_padding_size(assume_block_size)

	# print("assume_block_size: {}".format(assume_block_size))
	# print("prefix_padding_size: {}".format(prefix_padding_size))

	length_of_encrypted_unknown_string = len(encryption_oracle(b''))
	discovered_string = b''
	for i in range(length_of_encrypted_unknown_string):
		discovered_string += decrypt_byte(assume_block_size, prefix_padding_size, discovered_string)
	print(discovered_string.decode())


if __name__ == '__main__':
	# random_prefex, block_size and key are transparent to attackers
	block_size = AES.block_size
	key = generate_random_key(16)
	random_prefix = generate_random_key(Crypto.Random.random.randint(1, 32))
	# test
	print("random_prefix: {}".format(len(random_prefix)))
	# conduct of attack
	main()
