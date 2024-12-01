// ✨ Decompiled using OpenAI's ChatGPT o1-review model ✨

import CryptoKit

func runCryptoFunction() {
    // Step 1: Load P256 Private Key from Embedded Data
    let keyBytes: [UInt8] = [
        0x7c, 0x02, 0x2a, 0x7e, 0x53, 0x7e, 0x1a, 0x2d,
        0x44, 0x77, 0xd4, 0xf6, 0x20, 0x8b, 0x14, 0xdb,
        0x4e, 0x8d, 0x84, 0x19, 0xd6, 0x23, 0x5f, 0xf2,
        0x4e, 0x4b, 0x8d, 0x18, 0xf4, 0x2c, 0x76, 0xe2
    ]
    let keyData = Data(keyBytes)

    do {
        // Create the private key from data
        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: keyData)

        // Step 2: Extract Public Key
        let publicKey = privateKey.publicKey

        // Step 3: Create Sample Data
        let sampleText = "This is a sample text"
        guard let data = sampleText.data(using: .utf8) else {
            self.output = "Failed to convert text to data"
            return
        }

        // Step 4: Sign the Data
        let signature = try privateKey.signature(for: data)

        // Step 5: Verify the Signature
        let isValidSignature = publicKey.isValidSignature(signature, for: data)

        // Step 6: Convert Keys and Signature to Hex Strings
        let publicKeyData = publicKey.rawRepresentation
        let publicKeyHex = publicKeyData.map { String(format: "%02x", $0) }.joined()
        let signatureData = signature.derRepresentation
        let signatureHex = signatureData.map { String(format: "%02x", $0) }.joined()

        // Step 7: Construct an Output Message
        var outputMessage = "Original: \(sampleText)"
        outputMessage += "\n\nSignature is \(isValidSignature ? "valid." : "invalid.")"
        outputMessage += "\n\nPublic Key (Hex): \(publicKeyHex)"
        outputMessage += "\n\nSignature (Hex): \(signatureHex)"
        outputMessage += "\n\nVerification: \(isValidSignature ? "Success" : "Failure")"

        // Step 8: Update SwiftUI State Variable
        self.output = outputMessage

    } catch {
        // Error handling
        self.output = "An error occurred: \(error)"
    }
}
