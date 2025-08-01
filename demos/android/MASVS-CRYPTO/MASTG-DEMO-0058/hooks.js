var target = {
    category: "CRYPTO",
    demo: "0058",
    hooks: [
    {
      class: "android.security.keystore.KeyGenParameterSpec$Builder",
      methods: [
        "setBlockModes",
        "setRandomizedEncryptionRequired"
      ]
    },
    {
      class: "android.security.keystore.KeyProtection$Builder",
      methods: [
        "setBlockModes",
        "setRandomizedEncryptionRequired",
      ]
    }
  ]
}
