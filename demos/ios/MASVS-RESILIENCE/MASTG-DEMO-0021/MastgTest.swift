import SwiftUI

class MastgTest {
    static func mastgTest(completion: @escaping (String) -> Void) {
        let jailbreakDetails = JailbreakDetector.isDeviceJailbroken()
        completion(jailbreakDetails)
    }
}

class JailbreakDetector {
    static func isDeviceJailbroken() -> String {
        // Check if running on a simulator
        if DeviceUtils.isSimulator() {
            let simulatorName = ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] ?? "Unknown Simulator"
            return "Warning: Running on a simulator (\(simulatorName)).\n\nProof:\n\n" + collectJailbreakProof()
        }
        
        // Collect jailbreak proofs
        let proof = collectJailbreakProof()
        if proof.isEmpty {
            return "Jailbreak: False\n\nNo signs of a jailbreak detected."
        } else {
            return "Jailbreak: True\n\nProof:\n\n" + proof
        }
    }
    
    private static func collectJailbreakProof() -> String {
        var reasons = [String]()
        
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
            "/etc/apt",
            "/private/var/lib/undecimus",
            "/private/var/root/Library/PreferenceLoader/Preferences",
            "/private/etc/apt"
        ]
        
        for path in jailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                reasons.append("Detected jailbreak file or directory at \(path)")
            }
        }
        
        // Check 2: Custom URL schemes
        let urlSchemes = [
            "cydia://",
            "sileo://",
            "zebra://",
            "filza://"
        ]
        
        for scheme in urlSchemes {
            if let url = URL(string: scheme), UIApplication.shared.canOpenURL(url) {
                reasons.append("Able to open suspicious URL scheme: \(scheme)")
            }
        }
        
        // Check 3: Suspicious environment variables
        let suspiciousEnvVars = [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_FRAMEWORK_PATH",
            "DYLD_LIBRARY_PATH"
        ]
        
        for envVar in suspiciousEnvVars {
            if ProcessInfo.processInfo.environment[envVar] != nil {
                reasons.append("Suspicious environment variable detected: \(envVar)")
            }
        }
        
        // Check 4: Write access to system paths
        let paths = [
            "/private/jailbreak.txt",
            "/private/var/mobile/Library/jailbreak.txt"
        ]
        
        for path in paths {
            do {
                try "test".write(toFile: path, atomically: true, encoding: .utf8)
                try FileManager.default.removeItem(atPath: path)
                reasons.append("Write access detected at \(path)")
            } catch {
                continue
            }
        }
        
        return reasons.joined(separator: "\n")
    }
}

class DeviceUtils {
    static func isSimulator() -> Bool {
        return ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
    }
}
