tools = """
MASTG-TOOL-0032	Frida CodeShare	
MASTG-TOOL-0034	LIEF	
MASTG-TOOL-0098	iaito	
MASTG-TOOL-0033	Ghidra	
MASTG-TOOL-0100	re-flutter	
MASTG-TOOL-0037	RMS Runtime Mobile Security	
MASTG-TOOL-0038	objection	
MASTG-TOOL-0036	r2frida	
MASTG-TOOL-0031	Frida	
MASTG-TOOL-0035	MobSF	
MASTG-TOOL-0101	disable-flutter-tls-verification	
MASTG-TOOL-0040	MobSF for iOS	
MASTG-TOOL-0060	otool	
MASTG-TOOL-0061	Grapefruit	
MASTG-TOOL-0062	Plutil	
MASTG-TOOL-0058	MachoOView	
MASTG-TOOL-0064	Sileo	
MASTG-TOOL-0054	ios-deploy	
MASTG-TOOL-0073	radare2 for iOS	
MASTG-TOOL-0050	Frida-ios-dump	
MASTG-TOOL-0063	security	
MASTG-TOOL-0057	lldb	
MASTG-TOOL-0041	nm - iOS	
MASTG-TOOL-0059	optool	
MASTG-TOOL-0047	Cydia	
MASTG-TOOL-0069	Usbmuxd	
MASTG-TOOL-0067	swift-demangle	
MASTG-TOOL-0102	ios-app-signer	
MASTG-TOOL-0070	Xcode	
MASTG-TOOL-0045	class-dump-dyld	
MASTG-TOOL-0044	class-dump-z	
MASTG-TOOL-0042	BinaryCookieReader	
MASTG-TOOL-0071	Xcode Command Line Tools	
MASTG-TOOL-0039	Frida for iOS	
MASTG-TOOL-0056	Keychain-Dumper	
MASTG-TOOL-0065	simctl	
MASTG-TOOL-0046	Cycript	
MASTG-TOOL-0068	SwiftShield	
MASTG-TOOL-0074	objection for iOS	
MASTG-TOOL-0051	gdb	
MASTG-TOOL-0049	Frida-cycript	
MASTG-TOOL-0066	SSL Kill Switch 3	
MASTG-TOOL-0055	iProxy	
MASTG-TOOL-0072	xcrun	
MASTG-TOOL-0053	iOSbackup	
MASTG-TOOL-0043	class-dump	
MASTG-TOOL-0101	codesign	
MASTG-TOOL-0048	dsdump	
MASTG-TOOL-0020	JustTrustMe	
MASTG-TOOL-0024	Scrcpy	
MASTG-TOOL-0012	apkx	
MASTG-TOOL-0010	APKLab	
MASTG-TOOL-0023	RootCloak Plus	
MASTG-TOOL-0026	Termux	
MASTG-TOOL-0025	SSLUnpinning	
MASTG-TOOL-0013	Busybox	
MASTG-TOOL-0009	APKiD	
MASTG-TOOL-0015	Drozer	
MASTG-TOOL-0001	Frida for Android	
MASTG-TOOL-0029	objection for Android	
MASTG-TOOL-0011	Apktool	
MASTG-TOOL-0022	Proguard	
MASTG-TOOL-0018	jadx	
MASTG-TOOL-0017	House	
MASTG-TOOL-0005	Android NDK	
MASTG-TOOL-0028	radare2 for Android	
MASTG-TOOL-0021	Magisk	
MASTG-TOOL-0027	Xposed	
MASTG-TOOL-0008	Android-SSL-TrustKiller	
MASTG-TOOL-0019	jdb	
MASTG-TOOL-0099	FlowDroid	
MASTG-TOOL-0016	gplaycli	
MASTG-TOOL-0003	nm - Android	
MASTG-TOOL-0004	adb	
MASTG-TOOL-0014	Bytecode Viewer	
MASTG-TOOL-0007	Android Studio	
MASTG-TOOL-0103	uber-apk-signer	
MASTG-TOOL-0006	Android SDK	
MASTG-TOOL-0002	MobSF for Android	
MASTG-TOOL-0030	Angr	
MASTG-TOOL-0080	tcpdump	
MASTG-TOOL-0076	bettercap	
MASTG-TOOL-0079	OWASP ZAP	
MASTG-TOOL-0078	MITM Relay	
MASTG-TOOL-0077	Burp Suite	
MASTG-TOOL-0097	mitmproxy	
MASTG-TOOL-0075	Android tcpdump	
MASTG-TOOL-0081	Wireshark
"""
tooldict = {}
for tool in tools.split("\n"):
    toolid = tool[0:15].strip()
    toolname = tool[16:].lower().strip()
    tooldict[toolname] = toolid

    print(toolid, "----", toolname)


import os
import re

def find_words_in_md_files(directory):
    # Regex pattern to find words starting with @@@
    pattern = re.compile(r'@@@\w*')

    
    # Loop through all files in the directory and subdirectories
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.md'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    matches = pattern.findall(content)
                    if matches:
                        for match in matches:
                            # print(match[3:])
                            toolname = match[3:].strip()
                            if not toolname in tooldict.keys():
                                print("Missing: ", toolname)
                            else:
                                content = content.replace(toolname, tooldict[toolname])
                            
                        # print(f"File: {file_path}")
                        # print(f"Matches: {matches}")
                        # print()

# Run the function on the current directory
find_words_in_md_files('./MASTG')
