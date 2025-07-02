---
title: Software Composition Analysis (SCA) of iOS Dependencies by Creating a SBOM
platform: ios
---

You can use @MASTG-TOOL-0134 to create a Software Bill of Materials (SBOM) in the CycloneDX format if you use SwiftPM. Currently, Carthage and CocoaPods are not supported. You can either ask the development team to provide the SBOM file or create it yourself. To do so, navigate to the root directory of the Xcode project you wish to scan, then execute the following command:

```bash
$ cdxgen -o sbom.json
```

The SBOM file that was created needs to be Base64 encoded and uploaded to @MASTG-TOOL-0132 for analysis.

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

Also check the [alternatives for uploading](https://docs.dependencytrack.org/usage/cicd/) the SBOM file in case the produced JSON file is too large.

If you are using the default settings of the @MASTG-TOOL-0133 Docker container, go to the frontend of @MASTG-TOOL-0132, which is <http://localhost:8080>. Open the project to which you uploaded the SBOM to verify if there are any vulnerable dependencies.

> Note: Transitive dependencies are not supported by @MASTG-TOOL-0134 for [SwiftPM](https://cyclonedx.github.io/cdxgen/#/PROJECT_TYPES).
