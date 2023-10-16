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

## Caveats on current limitations
 * Only Linux platforms are supported at the moment.
 * Storage `Holder` does not endure process `fork`.
 * `unsafe`-saturated, so highly experimental.
 * Explicit memory mapping address specification on storage initialization is
   recommended.
 * Memory allocation quantum is 32 or 64 bytes on, respectively, 32 or 64-bit
   architectures.

## What's new in 0.1.2
- Custom `Allocator::shrink` and `grow` methods added to eliminate unnecessary
  data copies.
- Some new tests.
- MIT license option in addition to Apache v2.0 option.

## To do list
- Concurrent threads access tests to detect race conditions.
- 64 bytes allocation quantum may be too much. Two RBTrees holding free blocks
    may be too slow. Any suggestions on how to improve this?
- Window$ support.
- Main file page `mlock`-ing instead of log file immediate `fsync` in signal
    handler to increase write throughput and decrease latency.
- Test multi-process concurrent read and exclusive write access.
- 100% code lines test coverage. How to collect coverage of docs tests?

## License
[Apache License v2.0](tmfalloc/blob?file=LICENSE-APACHE) or
[MIT License](tmfalloc/blob?file=LICENSE-MIT)

## Author and feedback

Vladimir Voznesenskiy [\<vvoznesensky@yandex.ru\>](
    mailto:vvoznesensky@yandex.ru). Looking for interesting Rust job.

Comments, suggestions, bug reports, pull requests, praises and reasonable curses
are welcome.

