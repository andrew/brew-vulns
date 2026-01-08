# brew-vulns

A Homebrew subcommand that checks installed packages for known vulnerabilities using the [OSV.dev](https://osv.dev) database.

## Installation

Via Homebrew:

```bash
brew tap andrew/brew-vulns https://github.com/andrew/brew-vulns
brew install brew-vulns
```

Or via RubyGems:

```bash
gem install brew-vulns
```

Once installed, the command is available as `brew vulns`.

## Usage

```bash
# Check all installed packages
brew vulns

# Check a specific formula
brew vulns openssl

# Check a formula and its dependencies
brew vulns python --deps

# Output as JSON (useful for CI/CD)
brew vulns --json

# Show help
brew vulns --help
```

## How it works

1. Reads installed Homebrew formulae via `brew info --json=v2 --installed`
2. Extracts the GitHub repository URL and version tag from each formula's source URL
3. Queries the OSV API using the GIT ecosystem to find known vulnerabilities
4. Reports any vulnerabilities found with their severity and CVE identifiers

Only packages with GitHub source URLs can be checked. Packages from other sources are skipped.

## Example output

```
Checking 104 packages for vulnerabilities...
(119 packages skipped - no GitHub source URL)

expat (2.7.3)
  CVE-2025-66382 (HIGH) - XML parsing vulnerability...

hdf5 (1.14.6)
  OSV-2023-1091 (MEDIUM) - Buffer overflow in...
  OSV-2023-1223 (MEDIUM) - ...

Found 15 vulnerabilities in 3 packages
```

## Exit codes

- `0` - No vulnerabilities found
- `1` - Vulnerabilities found (or error occurred)

This makes it suitable for use in CI/CD pipelines.

## Development

```bash
git clone https://github.com/andrewnesbitt/brew-vulns
cd brew-vulns
bin/setup
rake test
```

## License

MIT License. See [LICENSE](LICENSE) for details.
