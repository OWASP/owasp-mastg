---
title: Demangling Symbols
platform: ios
---

To make some identifiers in the program unique, the compiler will process their symbol names. This process is called "name mangling" or simply "mangling". Often, the resulting symbols are hard to understand for humans. Additionally, their format is specific to the input language, the compiler and it may even be version dependent.

You can use demangling tools to revert the mangling process. For Swift there is @MASTG-TOOL-0067, for C++ function names there is @MASTG-TOOL-0122.md.

## swift-demangle

Pass the mangled symbol to @MASTG-TOOL-0067:

```bash
$ xcrun swift-demangle __T0So9WKWebViewCABSC6CGRectV5frame_So0aB13ConfigurationC13configurationtcfcTO
_T0So9WKWebViewCABSC6CGRectV5frame_So0aB13ConfigurationC13configurationtcfcTO ---> @nonobjc __C.WKWebView.init(frame: __C_Synthesized.CGRect, configuration: __C.WKWebViewConfiguration) -> __C.WKWebView
```

## c++filt

You can demangle C++ symbols with @MASTG-TOOL-0122:

```bash
c++filt _ZSt6vectorIiSaIiEE
std::vector<int, std::allocator<int>>
```
