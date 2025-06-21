import SwiftUI
import LocalAuthentication

struct MastgTest {
  
  static func mastgTest(completion: @escaping (String) -> Void) {
    if devicePasscodeSet(){
      completion("This device is protected with a passcode ✅")
    }
    else{
      completion("This device doesn't have a passcode ⚠️")
    }
  }
 
  static func devicePasscodeSet() -> Bool {
      // Use LAPolicy.deviceOwnerAuthentication to verify if the device has a passcode.
      // According to docs: "In iOS, policy evaluation fails with the error passcodeNotSet if the device passcode isn’t enabled"
      // Ref: https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthentication
      return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    }

}
