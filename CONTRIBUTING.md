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
./bin/test.sh 1.18
```

This will spin up a containerized Conjur environment and build the test containers,
and will run the tests in a `golang:1.18` container

Supported arguments are `1.18` and `1.19`, with the
default being `1.18` if no argument is given.

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

## Releasing

This project follows the standard [Conjur community release guidelines](https://github.com/cyberark/community/blob/main/Conjur/CONTRIBUTING.md#release-process).

In particular, for each release you should:

- Review the changes since the last release, and update the [version](./VERSION)
  following [semantic versioning](https://semver.org/).
- Determine whether any dependencies were added, removed, or updated in
  [`go.mod`](./go.mod) since the last release. If any changes have been made,
  update the [NOTICES](./NOTICES.txt) file.
- Update the [CHANGELOG](./CHANGELOG.md) to reflect the new version.
- Update the [VERSION](./VERSION) file to reflect the new version.
- Commit the changes to the files above in a branch and submit a version bump PR
- Once the PR has been merged, tag the version using
  `git tag -s vx.y.z -m vx.y.z`. Note: this requires you to be able to sign
  releases. Consult the [github documentation on signing commits](https://help.github.com/articles/signing-commits-with-gpg/).
- Push the tag by running `git push origin vx.y.z`
- Create a GitHub release for the tag, and copy the changelog for this version
  into the GitHub release description
