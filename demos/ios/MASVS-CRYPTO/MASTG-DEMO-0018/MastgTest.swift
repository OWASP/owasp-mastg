import SwiftUI
import CommonCrypto

struct MastgTest {
    static func mastgTest(completion: @escaping (String) -> Void) {
        let key = "0123456789abcdef01234567" // 24-byte key for 3DES
        let data = "This is a sample text".data(using: .utf8)!
        
        // Create a buffer for encrypted data
        var encryptedBytes = [UInt8](repeating: 0, count: data.count + kCCBlockSize3DES)
        var numBytesEncrypted: size_t = 0
        
        let cryptStatus = data.withUnsafeBytes { dataBytes in
            key.withCString { keyBytes in
                CCCrypt(
                    CCOperation(kCCEncrypt),              // Encrypt
                    CCAlgorithm(kCCAlgorithm3DES),        // 3DES Algorithm
                    CCOptions(kCCOptionPKCS7Padding),     // PKCS7 Padding
                    keyBytes, kCCKeySize3DES,             // Key and key length
                    nil,                                  // Initialization Vector (optional)
                    dataBytes.baseAddress, data.count,    // Input data
                    &encryptedBytes, encryptedBytes.count, // Output data
                    &numBytesEncrypted                    // Number of bytes encrypted
                )
            }
        }
        
        if cryptStatus == kCCSuccess {
            let encryptedData = Data(bytes: encryptedBytes, count: numBytesEncrypted)
            let encryptedHex = encryptedData.map { String(format: "%02hhx", $0) }.joined()
            let value = "Original:\n\n \(String(data: data, encoding: .utf8)!)\n\nEncrypted (Hex):\n \(encryptedHex)"
            completion(value)
        } else {
            completion("Encryption failed with status: \(cryptStatus)")
        }
    }
}
