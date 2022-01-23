# MSTG PDFs Generation with Docker

The MSTG document generation is based on pandocker: [https://github.com/dalibo/pandocker/blob/latest/LICENSE](https://github.com/dalibo/pandocker/blob/latest/LICENSE).

## On your Machine

- Install Docker
- `cd` to the MSTG root folder `owasp-mstg/`
- Run the `pandoc_makedocs.sh` script with the language folder and an optional version number (**do not `cd` into `tools/docker` to run it**):

    ```sh
    $ ./tools/docker/pandoc_makedocs.sh Document MyVersion
    ```

- You can set `VERBOSE=1` for a more detailed output

## On GitHub

Each time you push to GitHub the workflows in the [MSTG GitHub Actions](https://github.com/OWASP/owasp-mstg/actions "MSTG GitHub Actions") will be triggered. You can check what will be executed inside the folder `owasp-mstg/.github/workflows`, where `docgenerator.yml` takes care of building the Docker image and running the generation script once per language inside the container.

See the results in: <https://github.com/OWASP/owasp-mstg/actions>

## Generation Steps

### In case of a new Docker image

- Create a PR with the new changes on the Docker generation scripts.
- Once the PR is approved, create a tag:

  ```sh
    git tag -a docker-<docker-container-image-version> -m "Changes on docker image"
  ```

- Create a new image and push it to docker hub (requires being logged in to Docker hub and Docker hub membership of OWASP organization):

  ```sh
    docker build --tag owasp/masvs-docgenerator:<docker-container-image-version> tools/docker/
    docker images
    #check the output and find the tag of the MASVS-generator container image you created
    docker tag <imageid> owasp/masvs-docgenerator:<docker-container-image-version>
    docker push owasp/masvs-docgenerator:<docker-container-image-version>
  ```

- Create a new PR with the new version in the `docgenerator.yml` and `pandoc_makedocs.sh`.

### In case of a new document

Given a new version:

- Run Docker container which will run the generation script (`pandoc_makedocs.sh`).
- The script should be self explanatory, it basically:
  - Reads the `metadata.md` for the Document folder
  - Using that metadata creates the cover dynamically including language and version (no GIMP required anymore!)
  - For more details, read the inline comments in `pandoc_makedocs.sh`.
- The PDFs will be generated in the MSTG root folder.
