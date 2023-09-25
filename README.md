# TMFAlloc: Transactional Mapped File Allocator for Rust

Transactional memory-mapped file allocator inspired by
[POST++](https://github.com/knizhnik/POST--).

## Features
 * File-backed memory-mapped storage.
 * Implements std::alloc::Allocator trait, so usual std::collections::\*
   (except Hash\*), std::boxed::Box, etc. containers could be stored in and
   retreived from the file.
 * Single writer/multiple reader in multi-threaded code.
 * Write transactions exploiting memory page protection and copy-on-write log
   file.

## Caveats on current limitations
 * Implements the simpliest possible bump (stack) allocator to prove the concept
   of Rust memory mapped file allocator, so is not very useful.
 * Only libc (Linux, etc.) platforms are supported at the moment.
 * `unsafe`-saturated, so highly experimental.

## To do list
- Non-bump allocator with much less wasteful memory management.
- Window$ support.
- Main file page locking instead of log file immediate sync in signal handler
    to increase write throughput.

## Author and feedback

Vladimir Voznesenskiy <vvoznesensky@yandex.ru>. Looking for interesting Rust
job.

Comments, suggestions, pull requests, praises and reasonable curses are welcome.

