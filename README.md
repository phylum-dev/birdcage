# Birdcage

<div align="center">

![Birdcage logo](./assets/Birdcage.png)

</div>

## About

Birdcage is a cross-platform embeddable sandboxing library allowing restrictions
to Filesystem and Network operations using native operating system APIs.

Birdcage was originally developed for use by the [Phylum CLI] as an extra layer
of protection against potentially malicious dependencies (see the [blog post]
for details). To better protect yourself from these security risks, [sign up
now]!

[phylum cli]: https://github.com/phylum-dev/cli
[blog post]: https://blog.phylum.io/sandboxing-package-installations-arms-developers-with-defense-against-open-source-attacks-and-unintended-consequences/
[sign up now]: https://www.phylum.io/

Birdcage focuses **only** on Filesystem and Network operations. It **is not** a
complete sandbox preventing all side-effects or permanent damage. Applications
can still execute most system calls, which is especially dangerous when
execution is performed as root. Birdcage should be combined with other security
mechanisms, especially if you are executing known-malicious code.

## Usage

You can run applications inside Birdcage's sandbox by running the `sandbox`
example:

```bash
cargo run --example sandbox -- -e /usr/bin/echo -e /usr/lib echo "Hello, Sandbox\!"
```

Check out `cargo run --example sandbox -- --help` for more information on how to
use the example.

## Supported Platforms

 - Linux (5.13+) via [Landlock] and [seccomp]
 - macOS via `sandbox_init()` (aka Seatbelt).

[landlock]: https://www.kernel.org/doc/html/latest/userspace-api/landlock.html
[seccomp]: https://man7.org/linux/man-pages/man2/seccomp.2.html
