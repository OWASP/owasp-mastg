import SwiftUI
import LocalAuthentication

struct MastgTest {
  
  static func mastgTest(completion: @escaping (String) -> Void) {
    let authReason = "Sign In with Biometrics";
    LAContext().evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: authReason) { success, error in
      DispatchQueue.main.async{
        if success{
          completion("Authentication success")
        }
        else{
          completion("Authentication failure ⚠️")
        }
      }
    }
  }
}
