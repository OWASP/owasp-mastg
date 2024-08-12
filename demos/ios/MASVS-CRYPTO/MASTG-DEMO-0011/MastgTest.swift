import Foundation
import Security

struct MastgTest {
    static func mastgTest(completion: @escaping (String) -> Void) {
        
        // Step 1: Generate an RSA key pair with a 1024-bit key size
        let tag = "org.owasp.mas.rsa-1014".data(using: .utf8)!
        let keyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 1024,  // Using 1024-bit RSA key
            kSecPrivateKeyAttrs as String:
               [kSecAttrIsPermanent as String:    true,     // to store it in the Keychain
                kSecAttrApplicationTag as String: tag]      // to find and retrieve it from the Keychain later
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(keyAttributes as CFDictionary, &error) else {
            completion("Failed to generate private key: \(String(describing: error))")
            return
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            completion("Failed to generate public key")
            return
        }
        
        // Convert the private key to data (DER format)
        guard let privateKeyData = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
            completion("Failed to extract private key: \(String(describing: error))")
            return
        }
        
        // Encode the private key for display
        //let privateKeyBase64 = privateKeyData.base64EncodedString()
        let privateKeyHex = privateKeyData.map { String(format: "%02hhx", $0) }.joined()
        
        // Convert the public key to data (DER format)
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            completion("Failed to extract public key: \(String(describing: error))")
            return
        }

        // Encode the public key for display
        // let publicKeyBase64 = publicKeyData.base64EncodedString()
        let publicKeyHex = publicKeyData.map { String(format: "%02hhx", $0) }.joined()
        
        // Data to sign
        let dataToSign = "This is a sample text".data(using: .utf8)!
        
        // Step 2: Sign the data with the private key
        guard let signature = SecKeyCreateSignature(
            privateKey,
            SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256,
            dataToSign as CFData,
            &error
        ) else {
            completion("Signing failed: \(String(describing: error))")
            return
        }
        
        // Convert signature to hex string for display
        let signatureHex = (signature as Data).map { String(format: "%02hhx", $0) }.joined()
        
        // Step 3: Verify the signature with the public key
        let verificationStatus = SecKeyVerifySignature(
            publicKey,
            SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256,
            dataToSign as CFData,
            signature as CFData,
            &error
        )
        
        let verificationResult = verificationStatus ? "Signature is valid." : "Signature is invalid."
        
        let value = """
        Original: \(String(data: dataToSign, encoding: .utf8)!)
        
        Private Key (Hex): \(privateKeyHex)
        
        Public Key (Hex): \(publicKeyHex)
        
        Signature (Hex): \(signatureHex)
        
        Verification: \(verificationResult)
        """
        
        completion(value)
    }
}
