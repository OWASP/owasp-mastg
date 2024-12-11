---
title: Keychain-Dumper
platform: ios
source: https://github.com/ptoomey3/Keychain-Dumper
---

[Keychain-dumper](https://github.com/ptoomey3/Keychain-Dumper/releases "keychain-dumper") is an iOS tool to check which keychain items are available to an attacker once an iOS device has been jailbroken. In order to use the tool on modern versions of iOS, you need to follow a few steps. First, download the latest release from [the Keychain-Dumper releases page](https://github.com/ptoomey3/Keychain-Dumper/releases), and unzip the package. Next, download the [updateEntitlements.sh](https://raw.githubusercontent.com/ptoomey3/Keychain-Dumper/refs/heads/master/updateEntitlements.sh) script to the same directory. Modify the first line (`KEYCHAIN_DUMPER_FOLDER=/usr/bin`) to say `KEYCHAIN_DUMPER_FOLDER=/var/jb/usr/bin` to be compatible with rootless jailbreaks. If your device has a rooted jailbreak (e.g. palera1n) you can skip this step.

```bash
# Copy over the binary to /var/jb/usr/bin/
scp keychain_dumper mobile@<deviceip>:/var/jb/usr/bin/

# Copy over the updateEntitlements.sh script
scp updateEntitlements.sh mobile@<deviceip>:/var/jb/usr/bin/

# SSH into the device
ssh mobile@<deviceip>

# Go to the /var/jb/tmp directory and switch to root
cd /var/jb/usr/bin & sudo su

# Add executable permissions to both files
chmod +x keychain_dumper
chmod +x updateEntitlements.sh

# Run updateEntitlements.sh
./updateEntitlements.sh

# Run keychain_dumper
/var/jb/tmp/keychain_dump -h
```

By default, the script will give keychain_dump all the required entitlements to analyze the KeyChain for all installed applications. To focus on a single application, you can remove all unnecessary requirements:

```bash
# Extract entitlements
ldid -e /var/jb/tmp/keychain_dump > ent.xml

# Remove all non-needed entitlements from the <array> segment
nano ent.xml

# Assign the entitlements again
ldid -Sent.xml /var/jb/tmp/keychain_dump
```

For usage instructions please refer to the [Keychain-dumper](https://github.com/mechanico/Keychain-Dumper "keychain-dumper") GitHub page.
