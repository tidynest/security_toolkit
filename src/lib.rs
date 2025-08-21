//! Security Toolkit Library
//!
//! This library provides security utilities for password validation,
//! file hashing, network scanning, and file analysis.

/*
Commenting & error-handling conventions
--------------------------------------
- Keep *public* functions documented with `///` so `cargo doc` stays useful.
- Prefer `anyhow::Result<T>` in binaries and `thiserror` in libraries.
- Avoid swallowing errors; attach context (`with_context`) near I/O.
- Name things after *what they do*, not *how they do it*.
- Keep helpers small and pure so unit tests don't need the filesystem/network.
*/

pub mod password;
pub mod hash;
pub mod scan;
pub mod analyse;