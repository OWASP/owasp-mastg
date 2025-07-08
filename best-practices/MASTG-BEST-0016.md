---
title: Hiding sensitive content from screenshots before backgrounding
alias: hiding-sensitive-content-from-screenshots-before-backgrounding
id: MASTG-BEST-0016
platform: ios
---

Ensure that the app hides sensitive content, such as credit card details and passcodes, before entering the background state. The system takes a screenshot of the current app's view and stores it on the disk. An attacker may extract this screenshot from there.

Depending on the user interface, there are several ways to overlay the screen content:

1. SwiftUI Interface

```swift
    @Environment(\.scenePhase) private var scenePhase
    @State private var showPrivacyScreen = false
    var body: some Scene {
      WindowGroup {
        ZStack {
          ContentView()
          if showPrivacyScreen {
            Image("overlayImage")
                .resizable()
                .scaledToFill()
                .ignoresSafeArea()
                .transition(.opacity)
            }
          }
       }
       .onChange(of: scenePhase) { newPhase in
          switch newPhase {
          case .background, .inactive:
              showPrivacyScreen = true
          case .active:
                showPrivacyScreen = false
              
          default:
              break
          }
        }
    }
```

2. Scene Delegate Interface

```swift

func sceneDidBecomeActive(_ scene: UIScene) {
    removePrivacyView()
}

func sceneWillResignActive(_ scene: UIScene) {
    addPrivacyView()
}

var privacyImageView: UIImageView?

private func addPrivacyView() {
    guard let window = self.window else { return }

    let imageView = UIImageView(image: UIImage(named: "overlayImage"))
    imageView.contentMode = .scaleAspectFill
    imageView.frame = window.bounds
    imageView.autoresizingMask = [.flexibleWidth, .flexibleHeight]

    self.privacyImageView = imageView
    window.addSubview(imageView)
}


private func removePrivacyView() {
    privacyImageView?.removeFromSuperview()
    privacyImageView = nil
}

```

3. App Delegate Interface

```swift

private var privacyImageView: UIImageView?

func applicationDidEnterBackground(_ application: UIApplication) {
    addPrivacyView()
}

func applicationWillEnterForeground(_ application: UIApplication) {
    removePrivacyView()
}
```

Refer to the "[Testing Data Storage](../Document/0x06d-Testing-Data-Storage.md "Testing Data Storage")" chapter for more information and best practices on securely storing sensitive data.
