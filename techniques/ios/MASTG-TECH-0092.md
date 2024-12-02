---
title: Repackaging and Re-Signing
platform: ios
---

Tampering with an app invalidates the code signature of the main executable, so it won't run on a non-jailbroken device.

Before re-signing and IPA you need to obtain a developer provisioning profile and certificate, see @MASTG-TECH-0079.

The re-signing process can be done manually using @MASTG-TOOL-0102, or by using automated tools like @MASTG-TOOL-0117 or @MASTG-TOOL-0114.

## @MASTG-TOOL-0117

Create a directory `fastlane` and create a `Fastfile` file as described in the documentation for [resigning](https://docs.fastlane.tools/actions/resign/).

Example:

```yaml
lane :resignipa do
  resign(
    ipa: "<PATH-to-IPA/filename.ipa",
    signing_identity: "Apple Development: Foobar (STGXYCETF3)",
    provisioning_profile: "~/Library/MobileDevice/Provisioning Profiles/<FILE-NAME>.mobileprovision",
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

After having this set up once, you only need to change the path in the `Fastfile` for the IPA you want to resign and execute the command again.

More information can be found in the official documentation: ["Codesign an existing ipa file with fastlane resign"](https://docs.fastlane.tools/actions/resign/)
