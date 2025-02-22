# sops-pre-commit-hook

Ensure that secrets are encrypted using sops before commiting to git.

## Links
* Requires: [pre-commit](https://pre-commit.com/)
* Requires: [sops](https://github.com/getsops)
* [CNCF - sops](https://www.cncf.io/projects/sops/)
* [CNCF - Landscape](https://landscape.cncf.io/)

## Configuration file `.sops.yaml` exists
It looks for the sops configuration file `.sops.yaml` in the project root
or anywhere in the path above the file being tested.

If this file is found and it contains `creation_rules`, then the value of
`path_regex` for each of the defined rules is used to check if a file should
be encrypted or not.

If a file name doesn't match any of the defined values for `path_regex` it
will **NOT** be evaluated.

## No configuration file `.sops.yaml` exists

**ONLY** when no configuration file is found, then all `.*.ya?ml` files are checked
as having `kind: secret`, then they are evaluated.

## Installation
Enable this hook by adding this to your project's `.pre-commit-config.yaml`

```yaml
repos:
- repo: https://github.com/red-lichtie/sops-pre-commit-hook
  rev: v1.2.1
  hooks:
    - id: sops-pre-commit-hook
```

## License

This software is licensed under the LGPL V3 license (see the [LICENSE](LICENSE.md) file).