// Transaction protected arena for memory mapped file storage allocator
use std::libc
use std::sync::atomic::{atomic_load, atomic_compare_and_swap, atomic_sub}
use std::sync::atomic::Ordering
use std::sync::RWLock
use std::io::{Result, Error}
use std_semaphore

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

pub struct Arena {
    idx: u8,
    fd: c_int,
    log_fd: c_int, // Log file, consists of pairs (uint32 page #, page).
    addr: *mut c_void,
    size: size_t,
    page_size: size_t,
    lock: RwLock,
    readers: AtomicUsize,
}

// Not for user's direct use.
impl Arena {
    pub fn begin_read(&self) {
    }

    pub fn end_read(&self) {
    }

    pub fn begin_write(&self) {
        panic_syserr!(libc::flock(self.fd, libc::LOCK_EX));
    }

    pub fn commit_write(&self) {
        panic_syserr!(libc::ftruncate(self.log_fd, 0));
    }

    pub fn rollback_write(&self) {
        panic_syserr!(libc::ftruncate(self.log_fd, 0));
    }
}

fn initialize<const IDX: u8>(file_pfx: &str, arena_address: usize,
                arena_size: usize) -> std::io::Result<()> {
    let mut aowg = arenas[IDX].write().unwrap();
    let &mut ao = aowg.deref_mut();
    match ao {
        Some(a) => { panic!("Arena {} already initialized", IDX); },
        None => {
            let result: std::io::Result<()>
            let fname = String::format!("{}.obj", file_pfx);
            let fd = libc::open(fname.as_bytes(), libc::O_CREAT);
            if fd != -1 {
                let lname = String::format!("{}.log", file_pfx);
                let ld = libc::open(lname.as_bytes(), libc::O_CREAT);
                if fd != -1 {
                    let aa = arena_address as *mut c_void;
                    let page_size = libc::sysconf(libc::_SC_PAGE_SIZE);
                    assert_neq!(page_size, -1);
                    let addr = libc::mmap(aa, arena_size, PROT_READ,
                        libc::MAP_SHARED_VALIDATE|libc::MAP_FIXED_NOREPLACE,
                        fd, 0);
                    if addr == aa {
                        *ao = Arena {
                            idx: IDX,
                            fd: fd,
                            log_fd: ld,
                            addr: addr,
                            size: arena_size,
                            page_size: page_size,
                        };
                        ao.rollback();
                        return Ok(());
                    }
                    libc::close(ld);
                }
                libc::close(fd);
            }
            Err(std::io::Error::from_last_error())
        }
    }
}

fn finalize<const IDX: u8>() {
    let mut aowg = arenas[IDX].write().unwrap();
    let &mut ao = aowg.deref_mut();
    match ao {
        Some(a) => {
            self.rollback();
            panic_syserr!(libc::close(a.log_fd));
            panic_syserr!(libc::munmap(a.addr, a.size));
            panic_syserr!(libc::close(a.fd));
            ao = None;
        },
        None => panic!("Arena {} double finalization", IDX),
    }
}

// Array to hold optional 256 arenas.
macro_rules! array {
    (@accum (0, $($_es:expr),*) -> ($($body:tt)*))
        => {array!(@as_expr [$($body)*])};
    (@accum (1, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (0, $($es),*) -> ($($body)* $($es,)*))};
    (@accum (2, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (1, $($es,)* $($es),*) -> ($($body)*))};
    (@accum (4, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (2, $($es,)* $($es),*) -> ($($body)*))};
    (@accum (8, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (4, $($es,)* $($es),*) -> ($($body)*))};
    (@accum (16, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (8, $($es,)* $($es),*) -> ($($body)*))};
    (@accum (32, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (16, $($es,)* $($es),*) -> ($($body)*))};
    (@accum (64, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (32, $($es,)* $($es),*) -> ($($body)*))};
    (@accum (128, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (64, $($es,)* $($es),*) -> ($($body)*))};
    (@accum (256, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (128, $($es,)* $($es),*) -> ($($body)*))};

    (@as_expr $e:expr) => {$e};

    [$e:expr; $n:tt] => { array!(@accum ($n, $e) -> ()) };
}

pub static mut arenas: [RWLock<Option<mut Arena>>, 256] =
    array![RwLock<Option<mut Arena>>(None), 256];

