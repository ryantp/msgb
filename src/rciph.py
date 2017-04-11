#python3.5

''' FILENAME: $PYTHON/$SITE-PACKAGES/gitpy_algorithm/_udmi/rciph.py
[_udmi == `user defined module interface`]

a wrapper for rsa_cipher and rsa_decription (take from:
	[LOCALNAME: D:/gitf/theAlgorithms/python/ciphers/rsa_cipher.py]
	[SOURCE: https://github.com/TheAlgorithms/Python])

a little extra security for saving sensitive information

this will only be a wrapper to the encrypt and decrypt functions, to be imported into actual programs

*this module does NOT handle db interfacing, the actual app will handle that aspect '''

import settings

RSAPRIV = settings.priv
RSAPUBL = settings.pub

DEFAULT_BLOCK_SIZE = 128
BYTE_SIZE = 256

def getBlocksFromText(message, blockSize=DEFAULT_BLOCK_SIZE):
	messageBytes = message.encode('ascii')

	blockInts = []
	for blockStart in range(0, len(messageBytes), blockSize):
		blockInt = 0
		for i in range(blockStart, min(blockStart + blockSize, len(messageBytes))):
			blockInt += messageBytes[i] * (BYTE_SIZE ** (i % blockSize))
		blockInts.append(blockInt)
	return blockInts

def getTextFromBlocks(blockInts, messageLength, blockSize=DEFAULT_BLOCK_SIZE):
	message = []
	for blockInt in blockInts:
		blockMessage = []
		for i in range(blockSize - 1, -1, -1):
			if len(message) + i < messageLength:
				asciiNumber = blockInt // (BYTE_SIZE ** i)
				blockInt = blockInt % (BYTE_SIZE ** i)
				blockMessage.insert(0, chr(asciiNumber))
		message.extend(blockMessage)
	return ''.join(message)

def encryptMessage(message, key, blockSize=DEFAULT_BLOCK_SIZE):
	encryptedBlocks = []
	n, e = key

	for block in getBlocksFromText(message, blockSize):
		encryptedBlocks.append(pow(block, e, n))
	return encryptedBlocks

def decryptMessage(encryptedBlocks, messageLength, key, blockSize=DEFAULT_BLOCK_SIZE):
	decryptedBlocks = []
	n, d = key
	for block in encryptedBlocks:
		decryptedBlocks.append(pow(block, d, n))
	return getTextFromBlocks(decryptedBlocks, messageLength, blockSize)

def readKeyFile(keyFilename):
	fo = open(keyFilename)
	content = fo.read()
	fo.close()
	keySize, n, EorD = content.split(',')
	return (int(keySize), int(n), int(EorD))

def enc(rawmsg, blockSize = DEFAULT_BLOCK_SIZE):
	# returns an encrypted rawmsg
	# uses RSAPUBL
	if rawmsg:
		msg = rawmsg
	else:
		return '' # return empty string if no msg returned
	print("Preparing encryption...")

	#the following taken from `.../rsa_cipher.py[encryptAndWriteToFile()]`
	keySize, n, e = readKeyFile(RSAPUBL)
	if keySize < blockSize * 8:
	    sys.exit('ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or greater than the key size. Either decrease the block size or use different keys.' % (blockSize * 8, keySize))

	encryptedBlocks = encryptMessage(msg, (n, e), blockSize)

	for i in range(len(encryptedBlocks)):
	    encryptedBlocks[i] = str(encryptedBlocks[i])
	encryptedContent = ','.join(encryptedBlocks)
	encryptedContent = '%s_%s_%s' % (len(msg), blockSize, encryptedContent)
	return encryptedContent
	
def dec(encmsg):
	# returns decrypted message
	# uses RSAPRIV

	# the following taken from `.../rsa_cipher.py[readFromFileAndDecrypt()]`
	keySize, n, d = readKeyFile(RSAPRIV)
	messageLength, blockSize, encryptedMessage = encmsg.split('_')
	messageLength = int(messageLength)
	blockSize = int(blockSize)

	if keySize < blockSize * 8:
	    sys.exit('ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or greater than the key size. Did you specify the correct key file and encrypted file?' % (blockSize * 8, keySize))

	encryptedBlocks = []
	for block in encryptedMessage.split(','):
	    encryptedBlocks.append(int(block))

	return decryptMessage(encryptedBlocks, messageLength, (n, d), blockSize)



