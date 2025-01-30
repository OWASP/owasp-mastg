import SwiftUI
import MachO

struct MastgTest {
    static func checkDebuggerEntitlement() -> Bool {
        print("\n=== Starting Debug Check ===\n")
        
        // Method 1: Check Bundle Info
        print("Method 1: Checking Bundle Info")
        let bundleURL = Bundle.main.bundleURL
        print("📦 Bundle URL: \(bundleURL.path)")
        
        // Try to read Info.plist
        let infoPath = bundleURL.appendingPathComponent("Info.plist").path
        print("📄 Info.plist Path: \(infoPath)")
        
        if let infoDict = NSDictionary(contentsOfFile: infoPath) {
            print("📋 Info.plist Contents: \(infoDict)")
        }
        
        // Method 2: Check Executable
        print("\nMethod 2: Checking Executable")
        if let executablePath = Bundle.main.executablePath {
            print("📍 Executable Path: \(executablePath)")
            
            do {
                let fileManager = FileManager.default
                let attributes = try fileManager.attributesOfItem(atPath: executablePath)
                print("📊 File Attributes: \(attributes)")
                
                // Try reading with different methods
                let data = try Data(contentsOf: URL(fileURLWithPath: executablePath))
                print("📄 File Size: \(data.count) bytes")
                
                if data.count > 0 {
                    if let content = String(data: data, encoding: .ascii),
                       content.contains("get-task-allow") {
                        print("✅ Found get-task-allow in binary!")
                        return true
                    }
                }
            } catch {
                print("❌ Error reading executable: \(error)")
            }
        }
        
        // Method 3: Check Embedded.mobileprovision
        print("\nMethod 3: Checking Embedded.mobileprovision")
        let bundlePath = Bundle.main.bundlePath
        let provisionPath = (bundlePath as NSString).appendingPathComponent("embedded.mobileprovision")
        print("📄 Provision Path: \(provisionPath)")
        
        do {
            let provisionData = try Data(contentsOf: URL(fileURLWithPath: provisionPath))
            if let provisionString = String(data: provisionData, encoding: .ascii),
               provisionString.contains("get-task-allow") {
                print("✅ Found get-task-allow in provision profile!")
                return true
            }
            print("📄 Provision Size: \(provisionData.count) bytes")
        } catch {
            print("⚠️ No embedded provision profile found: \(error)")
        }
        
        // Method 4: Process Info
        print("\nMethod 4: Checking Process Info")
        let isDebugger = isDebuggerAttached()
        print("🔍 Debugger Attached: \(isDebugger)")
        if isDebugger {
            print("✅ Debugger detected!")
            return true
        }
        
        print("\n=== Debug Check Complete ===\n")
        return false
    }
    
    static func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let junk = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        assert(junk == 0, "sysctl failed")
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    static func mastgTest(completion: @escaping (String) -> Void) {
        let isDebuggable = checkDebuggerEntitlement()
        let result = """
        === Debug Detection Test ===
        
        Checking get-task-allow entitlement in executable...
        
        Result: \(isDebuggable ? "⚠️ WARNING" : "✅ SECURE")
        
        \(isDebuggable ?
            "This application has NO debugging detection check.\nThe get-task-allow entitlement is enabled in the executable." :
            "This application has proper debugging detection.\nThe get-task-allow entitlement is disabled in the executable.")
        
        Technical Details:
        - Checked executable file for entitlements
        - Searched for get-task-allow patterns
        - Checked process info for debugger
        - Current Status: \(isDebuggable ? "Debugging Enabled" : "Debugging Disabled")
        
        Please check the console log for detailed debugging information.
        
        ===========================
        """
        
        completion(result)
    }
}
