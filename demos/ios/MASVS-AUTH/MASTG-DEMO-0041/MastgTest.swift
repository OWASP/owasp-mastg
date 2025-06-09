import Foundation
import LocalAuthentication

struct MastgTest {

    static func mastgTest(completion: @escaping (String) -> Void) {
        let token = "8767086b9f6f976g-a8df76"
        let context = LAContext()
        let reason = "Authenticate to access your token"

        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
            DispatchQueue.main.async {
                if success {
                    completion("✅ Retrieved token: \(token)")
                    return
                }

                // Authentication failed: inspect the error code
                let message: String
                if let laError = error as? LAError {
                    switch laError.code {
                    case .userCancel:
                        message = "Authentication was cancelled by the user."
                    case .userFallback:
                        message = "User tapped the fallback button (e.g. entered a password)."
                    case .systemCancel:
                        message = "Authentication was cancelled by the system (e.g. another app came to foreground)."
                    case .passcodeNotSet:
                        message = "Passcode is not set on the device."
                    case .biometryNotAvailable:
                        message = "No biometric authentication is available on this device."
                    case .biometryNotEnrolled:
                        message = "The user has not enrolled any biometrics."
                    case .biometryLockout:
                        message = "Biometry is locked out due to too many failed attempts."
                    default:
                        // For any future or undocumented codes
                        message = laError.localizedDescription
                    }
                } else {
                    // Some other non‐LAError error
                    message = error?.localizedDescription ?? "Unknown authentication error."
                }

                completion("❌ \(message)")
            }
        }
    }
}
