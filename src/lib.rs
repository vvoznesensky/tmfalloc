// Transaction protected arena for memory mapped file storage allocator
use std::libc
use std::sync::atomic::{atomic_load, atomic_compare_and_swap, atomic_sub}
use std::sync::atomic::Ordering
use std::sync::RWLock
use std::io::{Result, Error}
use std_semaphore
XXX Use ctor crate for initialization of memory map and SEGV handler.
use ctor 

// Panic on file problems. No graceful error handling available on startup.
macro_rules! panic_syserr {
    ( $( $rval:expr ) ) => {
        let rval = $rval;
        if $rval == -1 {
            let errno = *libc::__errno_location();
            let se = libc::strerror(errno);
            assert!(errno > 0);
            panic!(concat!("System error #{}: {}"), errno, se);
        }
        rval
    }
}

////////////////////////////////////////////////////////////////////////////////
// Arena: internal structure to hold all the file and mapping stuff statically.
struct Arena {
    idx: u8,
    fd: libc::c_int,
    log_fd: libc::c_int, // Log file, consists of pairs (u32 page #, page).
    mem: RwLock<&mut[u8]>, // Protects memory slice and flock in LOCK_SH mode.
    size: libc::size_t,
    page_size: libc::c_long,
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

type OMA = Option<mut Arena>>;
pub static mut arenas: [RwLock<OMA>; 256] = array![RwLock<OMA>>(None); 256];

////////////////////////////////////////////////////////////////////////////////
// ArenaHolder: RAII fixture to initialize the database files and mmapping.
// Create it once in your code for every IDX that you have chosen.
// Do not mess up with the Root type: this crate cannot figure out if the type
// of root object has been changed someway.
pub struct ArenaHolder<const IDX: u8, Root>;

impl<const IDX: u8, Root> ArenaHolder {
    pub fn new(file_pfx: &str, arena_address: usize,
                    arena_size: usize) -> std::io::Result<Self> {
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
                            let s = unsafe{ std::slice::from_raw_parts_mut(
                                        addr as *mut u8, arena_size) };
                            *ao = Arena {
                                idx: IDX,
                                fd: fd,
                                log_fd: ld,
                                mem: RwLock::new(s),
                                page_size: page_size,
                                readers: AtomicUSize::new(0)
                            };
                            flock_w(fd);
                            rollback<false>(fd, ld, s, page_size);
                            unflock(fd);
                            return Ok(Self);
                        }
                        libc::close(ld);
                    }
                    libc::close(fd);
                }
                Err(std::io::Error::from_last_error())
            }
        }
    }
    pub fn write() -> WriteAccessor {
        self.lock.read().unwrap()
        XXX Извлечь Accessor-ы.
    }
    pub fn read() -> ReadAccessor {
        XXX
    }
}

impl<const IDX: u8, Root> Drop for ArenaHolder<IDX, Root> {
    fn drop(&mut self) {
        let mut aowg = arenas[IDX].write().unwrap();
        let &mut ao = aowg.deref_mut();
        match ao {
            Some(a) => {
                let mem = a.mem.try_write().unwrap();
                flock_w(a.fd);
                rollback<true>(a.fd, a.log_fd, mem, a.page_size);
                unflock(a.fd);
                panic_syserr!(libc::close(a.log_fd));
                panic_syserr!(libc::munmap(
                        mem.first_mut().unwrap(), mem.len()));
                panic_syserr!(libc::close(a.fd));
                ao = None;
            },
            None => panic!("Arena {} double finalization", IDX),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Very internal functions that does not know about Arena structure, but
// only manipulates fds and mapped memory.

// Internal rollback.
// Must be called for flock-ed fd in LOCK_EX mode and guaranteed exclusive
// access of mem for this thread among threads that have access to this fd.
// For further use in ArenaHolder and WriteAccessor.
fn rollback<const PAGES_WRITABLE: bool>(fd: libc::c_int, lfd: libc::c_int,
            mem: &mut[u8], page_size: libc::c_long) {
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
    let page_no: u32;
    while read_exactly(lfd, &mut page_no, 4) == 4 {
        let offset = page_no * page_size;
        let addr = &mem[offset] as *mut c_void;
        if !PAGES_WRITABLE {
            assert!(addr == libc::mmap(addr, page_size, libc::PROT_WRITE,
                libc::MAP_SHARED_VALIDATE|libc::MAP_FIXED, fd, offset);
        }
        panic_syserr!(libc::read(lfd, ptr, page_size));
        assert!(addr == libc::mmap(addr, page_size, libc::PROT_READ,
            libc::MAP_SHARED_VALIDATE|libc::MAP_FIXED, fd, offset);
    }
    truncate(lfd);
}

// Internal commit.
// Must be called for flock-ed fd in LOCK_EX mode and guaranteed exclusive
// access of mem for this thread among threads that have access to this fd.
// For further use in WriteAccessor.
fn commit(fd: libc::c_int, lfd: libc::c_int,
            mem: &mut[u8], page_size: libc::size_t) {
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
    loop {
        let addr = libc::mmap(mem.first_mut().unwarp(), mem.len(), PROT_READ,
            libc::MAP_SHARED_VALIDATE|libc::MAP_FIXED_NOREPLACE, fd, 0);
        panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
    }
    truncate(lfd);
}

// Read exactly count bytes or 0 from the file.
fn read_exactly(lfd: libc::c_int, buf: *mut c_void,
                count: libc::size_t) -> usize {
    let rval: usize = 0;
    let s: i32;
    while count > 0 && (s = panic_syserr!(libc::read(lfd, buf, count))) != 0 {
        rval += s;
        count -= s;
    }
    rval
}

// Making log file ready for the next transaction.
fn truncate(lfd: libc::c_int) {
    panic_syserr!(libc::ftruncate(lfd, 0));
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
}

// Flock the main file.
fn flock_w(fd: libc::c_int) {
    panic_syserr!(libc::flock(self.fd, libc::LOCK_EX));
}
fn flock_r(fd: libc::c_int) {
    panic_syserr!(libc::flock(self.fd, libc::LOCK_SH));
}
fn unflock(fd: libc::c_int) {
    panic_syserr!(libc::flock(self.fd, libc::LOCK_UN));
}

////////////////////////////////////////////////////////////////////////////////
// Read accessor to allow storage concurrent read access.

struct ReadAccessor<const IDX: u8, Root> {
    holder: &ArenaHolder<IDX>,
};

impl<const IDX: u8, Root> ReadAccessor<u8, Root> {
    fn root(&self) -> Root {
        match *arenas_read[IDX].borrow {
            
        }
    }
}
impl<const IDX: u8, Root> Dump for ReadAccessor<u8, Root> {
    fn dump(&mut self) {
        XXX сделать unflock, если получается mem.try_borrow_mut
    }
}

struct WriteAccessor<const IDX: u8, Root>;
impl WriteAccessor {
    fn dump(&mut self) {
        XXX утвердиться в том, что получается mem.borrow_mut
        XXX сделать unflock
    }
}

thread_local! {
    pub static mut arenas_write: [RefCell<Option<RwLockWriteGuard<'_, OMA>>>;
        256] = [RefCell::new(None); 256];
    pub static mut arenas_read: [RefCell<Option<RwLockReadGuard<'_, OMA>>>;
        256] = [RefCell::new(None); 256];
}

////////////////////////////////////////////////////////////////////////////////
// Allocator applicable for standard containers to make them persistent.
pub struct Allocator<const IDX: u8>;

impl<const ARENA_ID: u8> alloc::Allocator for Allocator<ARENA_ID> {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let a = &mut arenas[ARENA_ID]
        assert!(a.fd >= 0, "MMTS arena #{} not initalized", ARENA_ID)
        let s: size_t
        let b = current_bump.load(Ordering::Acquire)
        let na = a.addr.byte_offset(b)
        loop {
            s = (na as *u8).align_offset(layout.align()) + layout.size()
            let n = a.current_bump.compare_and_swap(b, b + s, Ordering::SeqCst)
            if n == b break;
            na = a.addr.byte_offset(b)
        }
        if b + s > a.size {
            return Err(AllocError::fmt("Out of MMTS arena #{}", ARENA_ID).
                       unwrap())
        } else {
            return Ok(NonNull::slice_from_raw_parts(na, s)
        }
    }
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

