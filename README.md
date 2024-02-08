# TMFAlloc: Transactional Mapped File Allocator for Rust

Transactional memory-mapped file allocator inspired by
[POST++](https://github.com/knizhnik/POST--). Allows to merge data
representation and storage tiers into one tier. May be used as fixed-schema
client cache, embedded application data storage, etc.

## Features
 * File-backed memory-mapped storage.
 * Implements `std::alloc::Allocator` trait, so usual `std::collections::*`
   (except `Hash*`), `std::boxed::Box`, etc. containers could be stored in and
   retreived from the file.
 * Single writer/multiple readers in multi-threaded code.
 * Write transactions exploit memory page protection and copy-on-write log
   file.
 * Storage has user-defined `Root` type generic parameter to
   store all application-specific parameters, collections, etc.
 * Storage file is `flock`-protected, so simultaneous processes access is
   possible.
 * Allocates the least but fittable free block with the lowest address among
   all equally-sized blocks.
 * Average allocation and deallocation cost is `O(log(number of free blocks))`
   (plus possible file operations costs).
 * Allows allocation arena expansion.
 * Runs on Linux and Windows.
 * Runs on 32- and 64-bit CPUs.

## Caveats on current limitations
 * Do not use the same storage `Holder` in both parent and `fork`-ed child
   processes.
 * It's not guaranteed if dangling pointers to unmapped storage memory could be
   avoided in case of some non-standard use. In particular,
   `tmfalloc::Allocator` can be cloned (this is a requirement of
   `std::BTreeMap`) and leak out of destructed storage `Holder`.
 * Memory mapping address cannot be changed after storage initialization. Hence,
   explicit memory mapping address specification on storage initialization is
   recommended.
 * Memory allocation quantum is 32 or 64 bytes on, respectively, 32 or 64-bit
   architectures, that may be percieved as wasteful.

## What's new in 1.0.0
 * Some documentation and API clearing.
 * In particular, `unsafe` function `Holder::open` replaces `Holder::new` and
   formally breaks backward compatibility, but improves correctness and sanity.
 * Fixed Rust 1.77 `std::collections::btree\_map::Cursor` API backward
   compatibility drop. Minimal Rust version increased to 1.77.
 * `Holder` now has `Send` trait.
 * New doctest for multi-process concurrent read and exclusive write access.

## To do list
 * Concurrent threads access tests to detect race conditions.
 * 64 bytes allocation quantum may be too much. Two RBTrees holding free blocks
   may be too slow. Any suggestions on how to improve this?
 * Main file page `mlock`-ing instead of log file immediate `fsync` in signal
   handler to increase write throughput and decrease latency.
 * 100% code lines test coverage. How to collect coverage of docs tests?
 * Do less RBTrees traversal on (de/re)allocations by (re)using already
   available pointers.

## License
[Apache License v2.0](tmfalloc/blob?file=LICENSE-APACHE) or
[MIT License](tmfalloc/blob?file=LICENSE-MIT)

## Author and feedback

Vladimir Voznesenskiy [\<vvoznesensky@gmail.com\>](
    mailto:vvoznesensky@gmail.com). Looking for a Rust job.

Feedback is welcome. Please, send me an email, if you need more tests, etc.

