# npm publication (not enabled yet)

This repository is public. The package has not been published to npm by this setup.

1. Confirm that the publisher has permission to publish under the `@spay` npm scope. Repository ownership alone does not grant npm scope ownership.
2. Run `npm ci`, `npm run check`, and `npm pack --dry-run`; inspect the file list.
3. Confirm the package name and version are available, update CHANGELOG.md, and tag the approved release.
4. Configure an npm trusted publisher for this repository, or use an npm account authorized for this scope with its required authentication controls.
5. Publish the reviewed package with public access and verify the registry entry. Never add an npm token to the repository.

No automatic publish workflow is enabled. CI validates builds and package contents only.
