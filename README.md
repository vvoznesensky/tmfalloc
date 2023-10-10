# TMFAlloc: Transactional Mapped File Allocator for Rust

Transactional memory-mapped file allocator inspired by
[POST++](https://github.com/knizhnik/POST--). May be useful as fixed-schema
client or embedded application data cache/storage, etc.

## Features
 * File-backed memory-mapped storage.
 * Implements `std::alloc::Allocator` trait, so usual `std::collections::\*`
   (except `Hash\*`), `std::boxed::Box`, etc. containers could be stored in and
   retreived from the file.
 * Single writer/multiple reader in multi-threaded code.
 * Write transactions exploit memory page protection and copy-on-write log
   file.
 * Every concrete storage has user-defined `Root` generic structure instance to
   store all the application-specific collections.
 * Storage file is `flock`-protected, so simultaneous processes access is
   possible.
 * Allocates the least but fittable free block with the least address among
   all equally-sized blocks.
 * Average allocation and deallocation cost is `O(log(number of free blocks))`
   (plus possible file operations costs).
 * Allows allocation arena expansion.

## Caveats on current limitations
 * Only Linux platforms are supported at the moment.
 * Storage `Holder` does not endure process `fork`.
 * `unsafe`-saturated, so highly experimental.
 * Explicit memory mapping address selection on storage initialization is
   recommended.
 * Memory allocation quantum is 32 or 64 bytes on, respectively, 32 or 64-bit
   architectures.

## What's new in 0.1.1
- `tests::page_boundary`: Test two adjastent pages border handling with 8-byte
    word write.
- `tests::read_recovery`: Fix and test broken transaction detection and rollback
    after `flock` in `Holder::read()` and `Holder::write()` to allow parallel
    writing process to crash.
- Memory areas overlapping detection test example in the crate's documentation.

## To do list
- Concurrent threads access tests to detect race conditions.
- `Allocator::shrink` and `grow` methods.
- 64 bytes allocation quantum may be too much. Two RBTrees holding free blocks
    may be too slow. Any suggestions on how to improve this?
- Window$ support.
- Main file page `mlock`-ing instead of log file immediate `fsync` in signal
    handler to increase write throughput and decrease latency.
- Test multi-process concurrent read and exclusive write access.

## Distribution license
[Apache License v2.0](tmfalloc/blob?file=LICENSE-APACHE)

## Author and feedback

Vladimir Voznesenskiy [\<vvoznesensky@yandex.ru\>](
    mailto:vvoznesensky@yandex.ru). Looking for interesting Rust job.

Comments, suggestions, bug reports, pull requests, praises and reasonable curses
are welcome.

