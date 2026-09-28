# libtpms-rs-compat

This project started because libtpms uses `longjmp`, which complicates using
the library from Go through WebAssembly.

C++ and Rust were considered. Rust was chosen to avoid an external C++
standard library dependency and for Cargo's build system.

The goal is to support this integration, not to rewrite everything in Rust.
