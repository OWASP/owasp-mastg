import Foundation
import CryptoKit

struct MastgTest {
    static func mastgTest(completion: @escaping (String) -> Void) {

        // Step 1: Use a hardcoded ECDSA P-256 private key (32 bytes for P-256) in bytes
        let privateKeyBytes: [UInt8] = [
            0x7c, 0x02, 0x2a, 0x7e, 0x53, 0x7e, 0x1a, 0x2d, 
            0x44, 0x77, 0xd4, 0xf6, 0x20, 0x8b, 0x14, 0xdb, 
            0x4e, 0x8d, 0x84, 0x19, 0xd6, 0x23, 0x5f, 0xf2, 
            0x4e, 0x4b, 0x8d, 0x18, 0xf4, 0x2c, 0x76, 0xe2
        ]
        let privateKeyData = Data(privateKeyBytes)
        
        guard let privateKey = try? P256.Signing.PrivateKey(rawRepresentation: privateKeyData) else {
            completion("Failed to create private key.")
            return
        }
        
        let publicKey = privateKey.publicKey
        
        // Data to sign
        let dataToSign = "This is a sample text".data(using: .utf8)!
        
        // Step 2: Sign the data with the hardcoded private key
        let signature = try! privateKey.signature(for: dataToSign)
        
        // Convert signature to hex string for display
        let signatureHex = signature.rawRepresentation.map { String(format: "%02hhx", $0) }.joined()
        
        // Step 3: Verify the signature with the public key
        let verificationStatus = publicKey.isValidSignature(signature, for: dataToSign)
        
        let verificationResult = verificationStatus ? "Signature is valid." : "Signature is invalid."
        
        let value = """
        Original: \(String(data: dataToSign, encoding: .utf8)!)
        
        Public Key (Hex): \(publicKey.rawRepresentation.map { String(format: "%02hhx", $0) }.joined())
        
        Signature (Hex): \(signatureHex)
        
        Verification: \(verificationResult)
        """
        
        completion(value)
    }
}
