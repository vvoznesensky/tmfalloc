# Rust's Memory Mapped Transactional Storage

## To do list

- Non-bump allocator with much less wasteful memory management.
- Window$ support.
- Main file page locking instead of log file immediate sync in signal handler
    to increase write throughput.
- Choose if to fail on bad magick or to wipe out old data.

