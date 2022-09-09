# Birdcage

**This library is still under development and not ready to be used yet.**

## About

Birdcage is a cross-platform embeddable sandboxing library allowing restrictions
to Filesystem and Network operations using native operating system APIs.

Birdcage **is not** a complete sandbox preventing all side-effects or permanent
damage. Applications can still execute most system calls, which is especially
dangerous when execution is performed as root. Do not use Birdcage as a safety
barrier for known-malicious code and keep other security mechanisms like user
restrictions in place.

## Usage

You can run applications inside Birdcage's sandbox by running the `sandbox`
example:

```bash
cargo run --example sandbox -- -e /usr/bin/echo -e /usr/lib echo "Hello, Sandbox\!"
```

Check out `cargo run --example sandbox -- --help` for more information on how to
use the example.
