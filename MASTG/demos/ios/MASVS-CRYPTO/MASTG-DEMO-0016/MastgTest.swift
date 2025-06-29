import Foundation
import CryptoKit

struct MastgTest {
    // Function to generate a SHA-1 hash
    static func generateSHA1Hash(data: Data) -> String {
        let hash = Insecure.SHA1.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    // Function to generate an MD5 hash
    static func generateMD5Hash(data: Data) -> String {
        let hash = Insecure.MD5.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    static func mastgTest(completion: @escaping (String) -> Void) {
        let input = "This is a sample text".data(using: .utf8)!
        
        // Generate SHA-1 hash
        let sha1Hash = generateSHA1Hash(data: input)
        
        // Generate MD5 hash
        let md5Hash = generateMD5Hash(data: input)
        
        let value = """
        Original: \(String(data: input, encoding: .utf8)!)
        SHA-1 Hash: \(sha1Hash)
        MD5 Hash: \(md5Hash)
        """
        
        completion(value)
    }
}
