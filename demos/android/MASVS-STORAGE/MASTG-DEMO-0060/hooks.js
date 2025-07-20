var target = {
  category: "STORAGE",
  demo: "0059",
  hooks: [
    {
      class: "android.app.SharedPreferencesImpl$EditorImpl",
      methods: [
        "putString",
        "putStringSet"
      ]
    },
    {
      class: "javax.crypto.Cipher",
      methods: [
        "getInstance",
        "doFinal",
        "init",
        "update",
      ]
    },
    {
      class: "java.security.KeyStore",
      methods: [
        // "getInstance",
        "setEntry",
        "getEntry"
      ]
    },
    {
      class: "javax.crypto.KeyGenerator",
      methods: [
        "getInstance",
        // "init",
        "generateKey"
      ]
    },
    {
      class: "android.util.Base64",
      methods: [
        "encodeToString",
        // "encode",
        "decode"
      ]
    },
    {
      class: "com.google.crypto.tink.DeterministicAead",
      methods: [
        "encryptDeterministically",
        "decryptDeterministically"
      ]
    },
    {
      class: "com.google.crypto.tink.subtle.Base64",
      methods: [
        "encode",
        "decode"
      ]
    },
    {
      class: "androidx.security.crypto.EncryptedSharedPreferences",
      methods: [
        "create",
        "edit"
      ]
    }
  ]
}
