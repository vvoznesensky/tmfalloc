# Rust's Memory Mapped Transactional Storage

## To do list

- Put the mapping address into header, check for it on loading.
- Non-bump allocator with much less wasteful memory management.
- Window$ support.
- Main file page locking instead of log file immediate sync in signal handler
    to increase write throughput.
- Fail on bad magick.

