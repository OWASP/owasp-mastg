import Foundation
import CoreData

class SensitiveDataHandlingExample {
    
    func storeUserToken() {
        // UserDefaults storage that might be backed up
        UserDefaults.standard.set("user_secret_token", forKey: "AuthToken")
        
        // Direct file creation that might be included in backups
        let sensitiveData = "Sensitive information".data(using: .utf8)!
        FileManager.default.createFile(atPath: "SensitiveData.txt", contents: sensitiveData, attributes: nil)
        
        // Loading data from a file, potential misuse could lead to sensitive data exposure
        let _ = try? Data(contentsOf: URL(fileURLWithPath: "path/to/sensitive/file"), options: .dataReadingMapped)
        
        // Reading a file into a string, potential for sensitive data exposure
        let _ = try? String(contentsOfFile: "path/to/another/sensitive/file")
        
        // Serializing an object without secure coding, might be insecure
        let userPreferences = ["theme": "dark", "notificationsEnabled": true]
        let _ = try? NSKeyedArchiver.archivedData(withRootObject: userPreferences, requiringSecureCoding: false, error: nil)
        
        // Creating a CoreData persistent store without encryption
        let container = NSPersistentContainer(name: "MyAppModel")
        container.persistentStoreDescriptions.first?.setValue(FileProtectionType.none.rawValue, forKey: "NSPersistentStoreFileProtectionKey")
        
        // Setting file attributes to disable encryption
        let filePath = "path/to/file/that/should/be/encrypted"
        try? FileManager.default.setAttributes([FileAttributeKey.protectionKey: FileProtectionType.none], ofItemAtPath: filePath)
    }
    
    func excludeFileFromBackup(filePath: String) {
        guard let url = URL(string: filePath) else { return }
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        try? url.setResourceValues(resourceValues)
    }
}
