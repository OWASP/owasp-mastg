# original source: https://github.com/github/codeql/blob/main/swift/ql/src/queries/Security/CWE-321/HardcodedEncryptionKey.swift

	// BAD: Using hardcoded keys for encryption
	let key: Array<UInt8> = [0x2a, 0x3a, 0x80, 0x05]
	let keyString = "this is a constant string"
	let ivString = getRandomIV()
	_ = try AES(key: key, blockMode: CBC(AES.randomIV(AES.blockSize)), padding: padding)
	_ = try AES(key: keyString, iv: ivString)
	_ = try Blowfish(key: key, blockMode: CBC(Blowfish.randomIV(Blowfish.blockSize)), padding: padding)
	_ = try Blowfish(key: keyString, iv: ivString)