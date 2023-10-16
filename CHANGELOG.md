# Changelog

Notable changes to Birdcage are documented in this file.

The sections should follow the order `Packaging`, `Added`, `Changed`, `Fixed` and `Removed`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Changed

- (Linux) Report invalid paths when adding exceptions
- `Exception::Write` changed to `Exception::WriteAndRead`

### Fixed

- (Linux) Root filesystem exceptions failing sandbox creation
- (Linux) Sandbox not enforcing readonly/noexec restrictions
- (Linux) Exceptions for special files (i.e. /dev/null)

## [0.4.0] - 2023-10-09

### Added

- (Linux) Seccomp system call filter

### Changed

- (Linux) Minimum Kernel version reduced to 3.8

### Fixed

- (Linux) Abstract namespace isolation
- (Linux) Socket and pipe isolation

### Contributors

We'd like to thank [@bjorn3](https://github.com/bjorn3) for disclosing an issue
with socket isolation.

## [0.3.1] - 2023-08-31

### Fixed

- Local sockets denied by network sandbox on Linux

## [0.3.0] - 2023-08-31

### Changed

- Linux seccomp network filtering now uses a whitelist instead of a blacklist
