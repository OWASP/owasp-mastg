removed from pinning:

#### What to Pin

When choosing what to pin you have to find a sensible balance between security and convenience.

- **CAs or Leaf Certificates?:**
  - **Root CA:** it's generally not recommended since it highly increases the risk. Trusting the root CA implies also trusting all its intermediate CAs.
  - **Intermediate CA:** trusting a specific intermediate CA reduces the risk but the app will be also trusting any other certificates issues by it, not only the ones meant for your app.
  - **Leaf Certificate:** recommended but must include backup (e.g. Intermediate CA). It provides 100% certainty that the app exclusively trusts the remote endpoints it was designed to connect to.
- **Certificate or Public Key?:** it is usually more convenient to pin to the public key (`SubjectPublicKeyInfo`) since it usually doesn't change even if the certificates rotate (are re-issued).

For example, the app pins the remote endpoint leaf certificate but includes a backup pin for the intermediate CA. This increases the risk by trusting more certificate authorities but decreases the chances of bricking your app. If there's any issue with the leaf certificate, the app can always fall back to the intermediate CA until you release an app update.

#### Where to store the Pins

There are several methods of including pins.

- Preloading (recommended): At development time, the certificate is embedded in the app package, hardcoded in the source code or network security configurations.
- Trust on first use (not recommended): At the time the app first connects to the remote endpoint the certificate can be retrieved and applied. However, this is not recommended because attackers intercepting the initial connection could inject their own certificates.

#### When the Pin Fails

Note that there are various options when dealing with a failing pin:

- Inform the user about not being able to connect to the backend and stop all operations. The app can check whether there is an update and inform the user about updating to the latest version of the app if available. The app allows no longer for any form of interaction with the user until it is updated or the pin works again.
- Do a call to a crash-reporting service including information about the failed pin. The responsible developers should get notified about a potential security misconfiguration.
- The app calls the backend using a TLS enabled call with no pinning to inform the backend of a pinning failure. The call can either differ in user-agent, JWT token-contents, or have other headers with a flag enabled as an indication of pinning failure.
- After calling the backend or crash-reporting service to notify about the failing pinning, the app can still offer limited functionality that shouldn't involve sensitive functions or processing of sensitive data. The communication would happen without SSL Pinning and just validate the X.509 certificate accordingly.

Which option(s) you choose depends on how important availability is compared to the complexity of maintaining the application.

- When a large amount of pin failures are reported to the backend or crash-reporting service, the developer should understand that there is probably a misconfiguration. There is a large chance that the key materials used at the TLS terminating endpoint is different than what the app is expecting. In that case, an update of either that key material or an update of the app should be pushed through.

- When only very few pin failures are reported, then the network should be ok, and so should be the configuration of the TLS terminating endpoint. Instead, it might well be that there is a man-in-the-middle attack ongoing at the app instance of which the pin is failing.