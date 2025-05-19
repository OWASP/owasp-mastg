---
title: dependency-track
platform: generic
source: https://github.com/DependencyTrack/dependency-track
---

[Dependency-Track](https://github.com/DependencyTrack/dependency-track) is a Component Analysis platform that allows organizations to identify and reduce risk in the software supply chain.

- **Installation**: You can install Dependency-Track by using [docker](https://docs.dependencytrack.org/getting-started/deploy-docker/). The default credentials can be found in the [initial setup](https://docs.dependencytrack.org/getting-started/initial-startup/).
- **Input**: Dependency-Track relies on Software Bill of Materials (SBOM) to identify vulnerable dependencies. SBOMs can be generated using tools such as @MASTG-TOOL-0134 and uploaded via the [API](https://docs.dependencytrack.org/usage/cicd/).
- **REST API**: You can use the REST API with an [API Key](https://docs.dependencytrack.org/integrations/rest-api/) and a project to which the SBOM can be uploaded.
