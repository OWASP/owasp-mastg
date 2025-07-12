import SwiftUI

struct MastgTest {
  
  static func mastgTest(completion: @escaping (String) -> Void) {
    // Check if screen is recorded
    if #available(iOS 17.0, *) {
      if let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene {
        let state = scene.keyWindow?.traitCollection.sceneCaptureState
        switch state {
          case .active:
            completion("Scene is actively being captured")
              
          case .inactive:
            completion("Scene capture is inactive")
              
          case .none:
            completion("Scene capture cannot be identified inactive")
          
          case .some(_):
            completion("Scene capture cannot be identified inactive")
          }
      } else {
        if UIScreen.main.isCaptured{
          completion("Scene is actively being captured")
        }
        else{
          completion("Scene capture is inactive")
        }
      }
    }
  }
}
