import CommonCrypto
import CryptoKit

let key_size = kCCKeySizeAES128

let plainData = "secret".data(using: .utf8)!

let key_weak = SymmetricKey(size: .bits128)
let encrypted = try AES.GCM.seal(plainData, using: key_weak, nonce: nil)
let decrypted = try AES.GCM.open(encrypted, using: key_weak)