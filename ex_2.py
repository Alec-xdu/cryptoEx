padding = input('get me a str\n')
padLen = len(padding)
lastLoc = 20 - padLen % 20
salt = '{:02x}'.format(lastLoc)
if lastLoc != 20:
	for i in range(0, lastLoc):
		padding += ('\\x' + salt)
print(padding)
