import binascii
import codecs
from hashlib import sha1
import base64
from Crypto.Cipher import AES


# 算校验位
def calcUnknownNum() -> int:
    unknownBit = 0
    number = '111116'
    weight = '731731'
    for i in range(0, 6):
        unknownBit += int(number[i]) * int(weight[i])
    return unknownBit % 10


# 获取K_seed
def getSeed(passportId: str) -> hex:
    return sha1(passportId.encode()).hexdigest()[:32]


def getKeys(ikeySeed: hex) -> list:
    salt = '00000001'  # 文件中规定要加的冗余
    ikeySeed = sha1(codecs.decode((ikeySeed+salt), 'hex')).hexdigest()[:32]
    # print(ikeySeed)
    keyList = [ikeySeed[:16], ikeySeed[16:32]]
    return keyList


# 奇偶校验
def parityCheck(key: hex) -> str:
    checkList = []
    binKey = bin(int(key, 16))[2:]
    for every7Bits in range(0, len(binKey), 8):
        if binKey[every7Bits:every7Bits+7].count('1') % 2 == 1:
            checkList.append(binKey[every7Bits:every7Bits+7])
            checkList.append('0')
        else:
            checkList.append(binKey[every7Bits:every7Bits+7])
            checkList.append('1')
    # print(hex(int(''.join(checkList), 2)))
    return hex(int(''.join(checkList), 2))


if __name__ == '__main__':
    passportNumber = '12345678<81110182111116' + str(calcUnknownNum())  # 将原护照号和校验位拼接
    keySeed = getSeed(passportNumber)  # 由护照号算K_seed
    key_A, key_B = getKeys(keySeed)     # 由k_seed生成k_A,K_B
    finalKEY = parityCheck(key_A)[2:] + parityCheck(key_B)[2:]  # 二者奇偶校验后拼接作为最终密钥
    text = '9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI'.encode(encoding='utf8')
    cipherText = base64.b64decode(text)
    print(binascii.unhexlify(finalKEY))
    IV = '0'*32
    plainText = AES.new(binascii.unhexlify(finalKEY), AES.MODE_CBC, binascii.unhexlify(IV))
    print(str(plainText.decrypt(cipherText).decode()))
