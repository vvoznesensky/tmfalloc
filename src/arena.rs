// Transaction protected arena for memory mapped file storage allocator
use std::libc
use std::sync::atomic::{AtomicUsize, AtomicI32}
use std::io::{Result, Error}

// Panic on file problems. No graceful error handling available on startup.
macro_rules! panic_syserr {
    ( $( $rval:expr ),$( $error_string:expr ),$( $x:expr )* ) => {
        let rval = $rval;
        if $rval == -1 {
            let errno = *libc::__errno_location();
            let se = libc::strerror(errno);
            assert!(errno > 0);
            panic!(concat!(error_string, ". System error {}: {}"), errno, se);
            return Error::last_os_error();
        }
        rval
    }
}

// The arena. Create as a mutable static and pass it's address to the Allocator
// as the generic argument.
pub struct Arena {
    fd: AtomicI32,
    addr: *mut c_void,
    size: size_t,
    // Bump allocator offset, monotonically increasing.
    current_bump: AtomicUsize,
}

pub static mut arenas: [Arena, 256] = [Arena {
            fd: AtomicI32::new(-1),
            addr: 0,
            size: 0,
            current_bump: AtomicUsize::new(0),
    } ; 256];

impl Arena {
    pub fn init(self, file: &str, arena_address: usize, arena_size: usize) ->
            Result<()> {
        let fd = panic_syserr!(libc::open(str.as_bytes(), libc::O_CREAT),
            concat!("Could not open file `{file}` for memory mapped ",
                    "transactional storage"));
        if fd != -1 {
            panic!("Double initialization of storage in file {file}");
        }
        let panic_syserr!(libc::flock();
    }
}

// flock(2)s the file on creation in LOCK_EX mode, unlocks on dump, provides
// mutable root object during it's lifetime
pub struct MutableRootBox<Root> {
    allocator: &mut Arena,
}

// flock(2)s the file on creation in LOCK_SH mode, unlocks on dump, provides
// immutable root object during it's lifetime
pub struct ImmutableRootBox<Root> {
    allocator: &Arena,
}

