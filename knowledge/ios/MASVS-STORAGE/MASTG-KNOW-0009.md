---
masvs_category: MASVS-STORAGE
platform: ios
title: Keyboard Cache
---

Several options, such as autocorrect and spell check, are available to users to simplify keyboard input and are cached by default in `.dat` files in `/private/var/mobile/Library/Keyboard/` and its subdirectories.

The [UITextInputTraits protocol](https://developer.apple.com/reference/uikit/uitextinputtraits "UITextInputTraits protocol") is used for keyboard caching. The `UITextField`, `UITextView`, and `UISearchBar` classes automatically support this protocol and it offers the following properties:

- `var autocorrectionType: UITextAutocorrectionType` determines whether autocorrection is enabled during typing. When autocorrection is enabled, the text object tracks unknown words and suggests suitable replacements, replacing the typed text automatically unless the user overrides the replacement. The default value of this property is `UITextAutocorrectionTypeDefault`, which for most input methods enables autocorrection.
- `var secureTextEntry: BOOL` determines whether text copying and text caching are disabled and hides the text being entered for `UITextField`. The default value of this property is `NO`.
