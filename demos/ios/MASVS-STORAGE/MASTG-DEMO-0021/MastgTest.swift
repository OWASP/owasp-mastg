import SwiftUI

struct MastgTest {
  
  static func mastgTest(completion: @escaping (String) -> Void) {
      // Base64 of "MAS_API_KEY=8767086b9f6f976g-a8df76"
      let reseponseFromServer = "TUFTX0FQSV9LRVk9ODc2NzA4NmI5ZjZmOTc2Zy1hOGRmNzY="
    
      // Decode the Base64 string and handle potential nil values
      guard let decodedData = Data(base64Encoded: reseponseFromServer),
            let decodedString = String(data: decodedData, encoding: .utf8) else {
          completion("Error: Failed to decode Base64 string.")
          return
      }
    
      completion("The secret in the memory held by this TextView: \(decodedString)")
  }
}
