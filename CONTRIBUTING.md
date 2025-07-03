# Contributing

For general contribution and community guidelines, please see the [community repo](https://github.com/cyberark/community).

## Contributing

1. [Fork the project](https://help.github.com/en/github/getting-started-with-github/fork-a-repo)
2. [Clone your fork](https://help.github.com/en/github/creating-cloning-and-archiving-repositories/cloning-a-repository)
3. Make local changes to your fork by editing files
3. [Commit your changes](https://help.github.com/en/github/managing-files-in-a-repository/adding-a-file-to-a-repository-using-the-command-line)
4. [Push your local changes to the remote server](https://help.github.com/en/github/using-git/pushing-commits-to-a-remote-repository)
5. [Create new Pull Request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request-from-a-fork)

From here your pull request will be reviewed and once you've responded to all
feedback it will be merged into the project. Congratulations, you're a
contributor!

## Development
To start developing and testing using our development scripts ,
the following tools need to be installed:

  - Docker
  - docker-compose

### Running tests

To run the test suite, run:
```shell
./bin/test.sh
```

This will spin up a containerized Conjur environment and build the test containers,
and will run all tests.

To run the tests against a specific version of Golang, you can run the following:
```shell
./bin/test.sh 1.21
```

This will spin up a containerized Conjur environment and build the test containers,
and will run the tests in a `golang:1.23` container

Supported arguments are `1.23` and `1.24`, with the
default being `1.23` if no argument is given.

### Setting up a development environment
To start a container with terminal access, and the necessary
test running dependencies installed, run:

```shell
./bin/dev.sh
```

You can then run the following command from the container terminal to run
all tests:

```shell
go test -coverprofile="output/c.out" -v ./... | tee output/junit.output;
exit_code=$?;
echo "Exit code: $exit_code"
```

## Releases

Releases should be created by maintainers only. To create a tag and release,
follow the instructions in this section.

### Update the changelog and notices (if necessary)
1. Update the `CHANGELOG.md` file with the new version and the changes that are included in the release.
1. Update `NOTICES.txt`
    ```sh-session
    go install github.com/google/go-licenses@latest
    # Verify that dependencies fit into supported licenses types.
    # If there is new dependency having unsupported license, that license should be
    # included to notices.tpl file in order to get generated in NOTICES.txt.
    $(go env GOPATH)/bin/go-licenses check ./... \
      --allowed_licenses="MIT,ISC,Apache-2.0,BSD-3-Clause,BSD-2-Clause,MPL-2.0" \
      --ignore $(go list std | awk 'NR > 1 { printf(",") } { printf("%s",$0) } END { print "" }')
    # If no errors occur, proceed to generate updated NOTICES.txt
    $(go env GOPATH)/bin/go-licenses report ./... \
      --template notices.tpl \
      --ignore github.com/cyberark/conjur-api-go \
      --ignore $(go list std | awk 'NR > 1 { printf(",") } { printf("%s",$0) } END { print "" }') \
      > NOTICES.txt
    ```

### Pre-requisites

1. Review the git log and ensure the [changelog](CHANGELOG.md) contains all
   relevant recent changes with references to GitHub issues or PRs, if possible.
   Also ensure the latest unreleased version is accurate - our pipeline generates 
   a VERSION file based on the changelog, which is then used to assign the version
   of the release and any release artifacts.
1. Ensure that all documentation that needs to be written has been 
   written by TW, approved by PO/Engineer, and pushed to the forward-facing documentation.
1. Scan the project for vulnerabilities

### Release and Promote

1. Merging into main/master branches will automatically trigger a release. If successful, this release can be promoted at a later time.
1. Jenkins build parameters can be utilized to promote a successful release or manually trigger aditional releases as needed.
1. Reference the [internal automated release doc](https://github.com/conjurinc/docs/blob/master/reference/infrastructure/automated_releases.md#release-and-promotion-process) for releasing and promoting.
