---
title: dependency-track
platform: generic
source: https://github.com/DependencyTrack/dependency-track
---

[Dependency-Track](https://github.com/DependencyTrack/dependency-track) is a Component Analysis platform that allows organizations to identify and reduce risk in the software supply chain.

You can install Dependency-Track by using [docker](https://docs.dependencytrack.org/getting-started/deploy-docker/). The default credentials can be found in the [initial setup](https://docs.dependencytrack.org/getting-started/initial-startup/).

Dependency-Track relies on Software Bill of Materials (SBOM) for identifying vulnerable  dependencies, which can be generated through @MASTG-TOOL-0119 and uploaded via [API](https://docs.dependencytrack.org/usage/cicd/).

To use the REST API you need to create an [API Key](https://docs.dependencytrack.org/integrations/rest-api/) and a project where the SBOM is uploaded to.
