import SwiftUI

struct MastgTest {
    static func mastgTest(completion: @escaping (String) -> Void) {
    // Define the file name and create the file URL
    let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
    let fileName = "secret.txt"
    var fileURL = documentsDirectory.appendingPathComponent(fileName)
  
    // Create the file content
    let fileContent = "MAS_API_KEY=8767086b9f6f976g-a8df76"
  
    do {
        try fileContent.write(to: fileURL, atomically: true, encoding: .utf8)
        
        // Set the isExcludedFromBackup flag
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        
        try fileURL.setResourceValues(resourceValues)
        
    } catch {
      completion("Error creating file: \(error)")
    }
    completion("File created and isExcludedFromBackup flag set to true")
    }
}
