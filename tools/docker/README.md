# MSTG PDFs Generation with Docker

The MSTG document generation is based on pandocker: [https://github.com/dalibo/pandocker/blob/latest/LICENSE](https://github.com/dalibo/pandocker/blob/latest/LICENSE).

## On your Machine

- Install Docker
- `cd` to the MSTG root folder `owasp-mstg/`
- Run the following and give a version number (**do not `cd` into `tools/docker` to run it**):

    ```sh
    $ ./tools/docker/run_docker_mstg_generation_on_local.sh 1.2
    ```

## On GitHub

Each time you push to GitHub the workflows in the [MSTG GitHub Actions](https://github.com/OWASP/owasp-mstg/actions "MSTG GitHub Actions") will be triggered. You can check what will be executed inside the folder `owasp-mstg/.github/workflows`, where `docgenerator.yml` takes care of building the Docker image and running the generation script once per language inside the container.

See the results in: <https://github.com/OWASP/owasp-mstg/actions>

## Generation Steps

### In case of a new Docker image

- Create a PR with the new changes on the Docker generation scripts.
- Once the PR is approved, create a tag:

  ```sh
    git tag -a docker-<docker-container-image-version> -m "Changeson docker image"
  ```

  - You would need to login first with `docker login`. Don't use your password but create a personal access token on <hub.docker.com>.

- Create a new image and push it to docker hub (requires being logged in to Docker hub and Docker hub membership of OWASP organization):

  ```sh
    docker build --tag owasp/mstg-docgenerator:<docker-container-image-version> tools/docker/
    docker images
    #check the output and find the tag of the mstg-generator container image you created
    docker tag <imageid> owasp/mstg-docgenerator:<docker-container-image-version>
    docker push owasp/mstg-docgenerator:<docker-container-image-version>
  ```

- You might be getting the error `denied: requested access to the resource is denied` when doing `docker push`. If that's the case try the following (Source: <https://github.com/docker/hub-feedback/issues/1222#issuecomment-572410689>):

  ```bash
  $ docker login --username=<username> --password-stdin && docker push owasp/mstg-docgenerator:<docker-container-image-version>
  ```

- Create a new PR with the new version of:
  - `/github/workflows/docgenerator.yml`
  - `/github/workflows/release.yml`
  - `tools/docker/run_docker_mstg_generation_on_local.sh`

### In case of a new document

Given a new version:

- Pull the image from docker hub (`docker pull owasp/mstg-generator:latest`)
- Run Docker container which will run the generation script (`pandoc_makedocs.sh`).
- The script should be self explanatory, it basically:
  - Reads the LANGUAGE-METADATA for the given VERSION and language folder
  - Using that metadata creates the cover dynamically including language and version (no GIMP required anymore!)
  - For the CJK languages it configures the latex-header file using the right packages and fonts.
  - For more details, read the inline comments in `pandoc_makedocs.sh`.
- The PDFs will be generated in the MSTG root folder.

## Open Points (REMOVE from here when DONE!)

- TBD
