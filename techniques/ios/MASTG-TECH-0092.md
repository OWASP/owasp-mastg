---
title: Signing IPA files
platform: ios
---

To install an IPA file on a non-jailbroken device, it needs to have a valid signature. On a jailbroken device, this is not required after installing @MASTG-TOOL-0127.

First, you need to obtain a developer provisioning profile and certificate, as explained in @MASTG-TECH-0079.

!!! Warning

    If you have a normal Apple account, you will only be able to sign the IPA with a modified (unique) Bundle identifier. If you have a Developer account, you can sign with the original Bundle identifier.

The signing process can be done using @MASTG-TOOL-0102, @MASTG-TOOL-0117, @MASTG-TOOL-0118 or @MASTG-TOOL-0114.

## Using fastlane

Create a directory `fastlane` and create a `Fastfile` file as described in the documentation for [resigning](https://docs.fastlane.tools/actions/resign/). Put both the `Fastfile` and your IPA in the `fastlane` directory.

Example:

```yaml
lane :resignipa do
  resign(
    ipa: "./filename.ipa",
    signing_identity: "Apple Development: MAS@owasp.org (LVGBSLUQB4)",
    provisioning_profile: "./embedded.mobileprovision",
  )
end
```

Afterwards, execute the `fastlane resignipa` command.

```bash
$ fastlane resignipa
[✔] 🚀 
[15:21:51]: Get started using a Gemfile for fastlane https://docs.fastlane.tools/getting-started/ios/setup/#use-a-gemfile
[15:21:52]: Driving the lane 'resignipa' 🚀
[15:21:52]: --------------------
[15:21:52]: --- Step: resign ---
[15:21:52]: --------------------
...
[15:22:03]: Successfully signed /test.ipa!
[15:22:03]: Successfully re-signed .ipa 🔏.

+-----------------------------+
|      fastlane summary       |
+------+--------+-------------+
| Step | Action | Time (in s) |
+------+--------+-------------+
| 1    | resign | 11          |
+------+--------+-------------+

[15:22:03]: fastlane.tools finished successfully 🎉
```

Once this is set up, all you need to do is change the path in the `Fastfile` for the IPA you want to resign and run the command again.

More information can be found in the official documentation: ["Codesign an existing ipa file with fastlane resign"](https://docs.fastlane.tools/actions/resign/)

!!! warning

    By default, fastlane will always use the Bundle identifier from the given provisioning profile, both for normal Apple accounts and Developer accounts. If you have a Developer account, you can specify the desired Bundle identifier by directly using the `resign.sh` script bundled with Fastlane and specifying the `--bundle-id` property:

    ```bash
    $ /opt/homebrew/Cellar/fastlane/2.226.0/libexec/gems/fastlane-2.226.0/sigh/lib/assets/resign.sh /Users/MAS/uncrackable1.ipa <CERTIFICATE> -p /Users/MAS/embedded.mobileprovision /Users/MAS/signed.ipa -v --bundle-id "org.mas.myapp"

    Specified provisioning profile: '/Users/MAS/embedded.mobileprovision'
    Original file: '/Users/MAS/uncrackable1.ipa'
    Certificate: '<CERTIFICATE>'
    Specified bundle identifier: 'org.mas.myapp'
    Output file name: '/Users/MAS/signed.ipa'
    Current bundle identifier is: 'org.mas.testapp'
    New bundle identifier will be: 'org.mas.myapp'
    Validating the new provisioning profile: /Users/MAS/embedded.mobileprovision
    Profile app identifier prefix is '6FZT6QZ6X3'
    Profile team identifier is '6FZT6QZ6X3'
    Updating the bundle identifier from 'org.mas.testapp' to 'org.mas.myapp'
    Fixing nested app and extension references
    Extracting entitlements from provisioning profile
    Resigning application using certificate: '<CERTIFICATE>'
    and entitlements from provisioning profile: /Users/MAS/embedded.mobileprovision
    _floatsignTemp/Payload/UnCrackable Level 1.app: replacing existing signature
    _floatsignTemp/Payload/UnCrackable Level 1.app: signed app bundle with Mach-O universal (armv7 arm64) [org.mas.myapp]
    Repackaging as /Users/MAS/signed.ipa
    ```

## Using Sideloadly

Sideloadly can take care of obtaining a valid certificate for your app, but it is not possible to simply sign an existing IPA file in-place. Sideloadly will sign the given IPA file and directly install it on the connected device. When using a normal Apple account, Sideloadly will modify the original package name by appending your team identifier (e.g. `sg.vp.UnCrackable1` becomes `sg.vp.UnCrackable1.QH868V5764`)
