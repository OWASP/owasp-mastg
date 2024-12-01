// ✨ Decompiled using OpenAI's ChatGPT o1-review model ✨

import Security

func runCryptoFunction() {
    // Step 1: Load RSA Private Key from Embedded Data
    // The key data is hardcoded and embedded in the binary
    let keyBytes: [UInt8] = [
        // The bytes from the data provided
        0x30, 0x82, 0x02, 0x5b, 0x02, 0x01, 0x00, 0x02,
        0x81, 0x81, 0x00, 0xbd, 0xf6, 0x89, 0x8f, 0xbd,
        0x0c, 0xe6, 0x4f, 0x9a, 0x97, 0xec, 0x30, 0x1a,
        // ...
        // For brevity, the full key data is not shown
    ]
    let keyData = Data(keyBytes)

    // Key attributes for creating the key
    let keyDict: [String: Any] = [
        kSecAttrKeyType as String:            kSecAttrKeyTypeRSA,
        kSecAttrKeyClass as String:           kSecAttrKeyClassPrivate,
        kSecAttrKeySizeInBits as String:      1024,
        kSecReturnPersistentRef as String:    true,
    ]

    var error: Unmanaged<CFError>?

    // Create the private key from the data
    guard let privateKey = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, &error) else {
        let errorMessage = "Failed to create private key: \(error!.takeRetainedValue() as Error)"
        self.output = errorMessage
        return
    }

    // Step 2: Extract Public Key
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        let errorMessage = "Failed to generate public key"
        self.output = errorMessage
        return
    }

    // Step 3: Create Sample Data
    let sampleText = "This is a sample text"
    guard let data = sampleText.data(using: .utf8) else {
        self.output = "Failed to convert text to data"
        return
    }

    // Step 4: Sign the Data
    let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
    guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
        self.output = "Algorithm not supported for signing"
        return
    }
    guard let signatureData = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data? else {
        let errorMessage = "Signing failed: \(error!.takeRetainedValue() as Error)"
        self.output = errorMessage
        return
    }

    // Step 5: Verify the Signature
    guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
        self.output = "Algorithm not supported for verification"
        return
    }
    let isVerified = SecKeyVerifySignature(publicKey, algorithm, data as CFData, signatureData as CFData, &error)

    // Step 6: Convert Keys and Signature to Hex Strings
    guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
        let errorMessage = "Failed to extract public key: \(error!.takeRetainedValue() as Error)"
        self.output = errorMessage
        return
    }
    let publicKeyHex = publicKeyData.map { String(format: "%02x", $0) }.joined()
    let signatureHex = signatureData.map { String(format: "%02x", $0) }.joined()

    // Step 7: Construct an Output Message
    var outputMessage = "Original: \(sampleText)"
    outputMessage += "\n\nSignature is \(isVerified ? "valid." : "invalid.")"
    outputMessage += "\n\nPublic Key (Hex): \(publicKeyHex)"
    outputMessage += "\n\nSignature (Hex): \(signatureHex)"
    outputMessage += "\n\nVerification: \(isVerified ? "Success" : "Failure")"

    // Step 8: Update SwiftUI State Variable
    self.output = outputMessage
}
