import SwiftUI

class MastgTest {
    static func mastgTest(completion: @escaping (String) -> Void) {
        let isJailbroken = JailbreakDetector.isDeviceJailbroken()
        let status = isJailbroken ? "Device is jailbroken!" : "Device is not jailbroken"
        completion(status)
    }
}

class JailbreakDetector {
    static func isDeviceJailbroken() -> Bool {
        // Check 1: Common jailbreak files and directories
        let jailbreakPaths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Applications/Installer.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/libexec/cydia",
            "/usr/libexec/ssh-keysign",
            "/usr/sbin/sshd",
            "/usr/bin/ssh",
            "/var/cache/apt",
            "/var/lib/apt",
            "/var/lib/cydia",
            "/var/log/syslog",
            "/bin/bash",
            "/bin/sh",
            "/etc/apt"
        ]
        
        for path in jailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        // Check 2: Check if app can open custom URL schemes
        let urlSchemes = [
            "cydia://",
            "sileo://",
            "zebra://",
            "filza://"
        ]
        
        for scheme in urlSchemes {
            if let url = URL(string: scheme) {
                if UIApplication.shared.canOpenURL(url) {
                    return true
                }
            }
        }
        
        // Check 3: Check for suspicious environment variables
        let suspiciousEnvVars = [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_FRAMEWORK_PATH",
            "DYLD_LIBRARY_PATH"
        ]
        
        for envVar in suspiciousEnvVars {
            if ProcessInfo.processInfo.environment[envVar] != nil {
                return true
            }
        }
        
        // Check 4: Try writing to system paths
        let paths = [
            "/private/jailbreak.txt",
            "/private/var/mobile/Library/jailbreak.txt"
        ]
        
        for path in paths {
            do {
                try "test".write(toFile: path, atomically: true, encoding: .utf8)
                try FileManager.default.removeItem(atPath: path)
                return true
            } catch {
                continue
            }
        }
        
        return false
    }
}
