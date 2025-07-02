---
title: PlistBuddy
platform: ios
host:
- macOS
---

PlistBuddy is available on macOS and allows you to print and modify `.plist` files. It is not on the default PATH, but it can be run via `/usr/libexec/PlistBuddy`. PlistBuddy uses a custom syntax to execute commands on the given plist file.

## Printing a Plist File

The example below prints an ASCII representation of the Info.plist file of @MASTG-APP-0025 by specifying the `Print` command:

```bash
/usr/libexec/PlistBuddy -c "Print" Info.plist
Dict {
    DTXcode = 0821
    DTSDKName = iphoneos10.2
    CFBundleName = UnCrackable Level 1
    UILaunchStoryboardName = LaunchScreen
    CFBundleIcons~ipad = Dict {
        CFBundlePrimaryIcon = Dict {
            CFBundleIconFiles = Array {
                AppIcon-120x20
                AppIcon-129x29
                AppIcon-140x40
                AppIcon-157x57
                AppIcon-160x60
                AppIcon-150x50
                AppIcon-172x72
                AppIcon-176x76
                AppIcon-183.5x83.5
            }
        }
    }
    DTSDKBuild = 14C89
    CFBundleDevelopmentRegion = en
    CFBundleVersion = 1
    BuildMachineOSBuild = 15G1212
    DTPlatformName = iphoneos
    CFBundleShortVersionString = 1.0
    UIMainStoryboardFile = Main
    CFBundleSupportedPlatforms = Array {
        iPhoneOS
    }
    CFBundlePackageType = APPL
    CFBundleInfoDictionaryVersion = 6.0
    UIRequiredDeviceCapabilities = Array {
        armv7
    }
    CFBundleExecutable = UnCrackable Level 1
    DTCompiler = com.apple.compilers.llvm.clang.1_0
    UISupportedInterfaceOrientations~ipad = Array {
        UIInterfaceOrientationPortrait
        UIInterfaceOrientationPortraitUpsideDown
        UIInterfaceOrientationLandscapeLeft
        UIInterfaceOrientationLandscapeRight
    }
    CFBundleIdentifier = sg.vp.UnCrackable1
    MinimumOSVersion = 8.0
    DTXcodeBuild = 8C1002
    DTPlatformVersion = 10.2
    LSRequiresIPhoneOS = true
    UISupportedInterfaceOrientations = Array {
        UIInterfaceOrientationPortrait
        UIInterfaceOrientationLandscapeLeft
        UIInterfaceOrientationLandscapeRight
    }
    CFBundleDisplayName = UnCrackable1
    CFBundleIcons = Dict {
        CFBundlePrimaryIcon = Dict {
            CFBundleIconFiles = Array {
                AppIcon-120x20
                AppIcon-129x29
                AppIcon-140x40
                AppIcon-157x57
                AppIcon-160x60
            }
        }
    }
    UIDeviceFamily = Array {
        1
        2
    }
    DTPlatformBuild = 14C89
}
```

You can also print specific entries. Dictionary properties are specified via `:` and array indices are 0-based. The command below prints the third app icon format:

```bash
/usr/libexec/PlistBuddy -c "Print CFBundleIcons~ipad:CFBundlePrimaryIcon:CFBundleIconFiles:2" Info.plist
AppIcon-140x40
```

## Changing Plist Values

PlistBuddy can also change values via the `Set <key> <value>` command. The following example updates the CFBundleDisplayName:

```bash
/usr/libexec/PlistBuddy -c "Set CFBundleDisplayName 'My New App Name'" Info.plist
/usr/libexec/PlistBuddy -c "Print CFBundleDisplayName" Info.plist
My New App Name
```

## Adding and Deleting Plist Values

Entries can be added and deleted by specifying the key, value and type:

```bash
/usr/libexec/PlistBuddy -c "Add CustomDictionary dict" Info.plist
/usr/libexec/PlistBuddy -c "Add CustomDictionary:CustomProperty string 'OWASP MAS'" Info.plist
/usr/libexec/PlistBuddy -c "Print CustomDictionary" Info.plist
Dict {
    CustomProperty = OWASP MAS
}
```
