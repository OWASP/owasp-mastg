---
title: Software Composition Analysis (SCA) of iOS Dependencies by Creating a SBOM
platform: ios
---

@MASTG-TOOL-0119 can be used to create a so called Software Bill of Material (SBOM) in the CycloneDX format in case SwiftPM is used (Carthage and CocoaPods are not supported yet). Either you ask the development team to provide the SBOM file to you, or you create the SBOM by yourself. To do this, navigate to the root directory of the Xcode project you want to scan and execute the following command:

```bash
$ cdxgen -o sbom.json
```

The created SBOM file need to be Base64 encoded and can then be uploaded to @MASTG-TOOL-0117 for analysis:

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

Check also [alternatives for uploading](https://docs.dependencytrack.org/usage/cicd/) the SBOM file, in case the produced json file is too large.

Go to the frontend of @MASTG-TOOL-0117, which is <http://localhost:8080>, if you are using the default settings of the @MASTG-TOOL-0118 docker container. Open the project you uploaded the SBOM to and you can verify if there are any vulnerable dependencies.

> Note: Transitive dependencies are not supported by @MASTG-TOOL-0119 for [SwiftPM](https://cyclonedx.github.io/cdxgen/#/PROJECT_TYPES).
