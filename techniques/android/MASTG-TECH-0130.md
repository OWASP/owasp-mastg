---
title: Software Composition Analysis (SCA) of Android Dependencies by Creating a SBOM
platform: android
---

@MASTG-TOOL-0134 can be used to create a so called Software Bill of Material (SBOM) in the CycloneDX format. Navigate to the root directory of the Android Studio project you want to scan and execute the following command:

```bash
$ cdxgen -t java -o sbom.json
```

The created SBOM file need to be Base64 encoded and can then be uploaded to @MASTG-TOOL-0132 for analysis:

```bash
$ cat sbom.json | base64
$ curl -X "PUT" "http://localhost:8081/api/v1/bom" \
     -H 'Content-Type: application/json' \
     -H 'X-API-Key: <YOUR API KEY>>' \
     -d $'{
  "project": "<YOUR PROJECT ID>",
  "bom": "<BASE64-ENCODED SBOM>"
  }'
```

Go to the frontend of dependency-check, which is <http://localhost:8080>, if you are using the default settings of the dependency-track docker container. Open the project you uploaded the SBOM to and you can verify if there are any vulnerable dependencies.

> Note: Transitive dependencies are supported by @MASTG-TOOL-0132 for [Java and Kotlin](https://cyclonedx.github.io/cdxgen/#/PROJECT_TYPES).
