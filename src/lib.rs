//! # TMFAlloc: Transactional Mapped File Allocator for Rust
//!
/*//! ## Storage initialization
//! ```
//! ##[derive(Default)]
//! struct S { /* some fields */ };
//! let h = tmfalloc::Holder::<S>::new("abcdef123456789", None, tmfalloc::TI,
//!                                               0xabcdef1234567890).unwrap();
//! ```
//!
//! ## Commited data in storage becomes persistent
//! ```
//! ##[derive(Default)]
//! struct S(u64);
//! let mut h1 = tmfalloc::Holder::<S>::new("1234567890abcdef", None,
//!                                 tmfalloc::TI, 0x1234567890abcdef).unwrap();
//! let mut w = h1.write();
//! w.0 = 31415926;
//!
//! w.commit();
//! drop(w);
//! drop(h1);
//!
//! let h2 = tmfalloc::Holder::<S>::new("1234567890abcdef", None,
//!                                 tmfalloc::TI, 0x1234567890abcdef).unwrap();
//! let r = h2.read();
//! assert_eq!(r.0, 31415926);
//! ```
//!
//! ## Data changes can be rolled back
//! ### Explicitly
//! ```
//! ```
//!
//! ### Implicitly
//! ```
//! ```
//!
//! ## Allocator make standard collections persistent
//! ```
//! ```
//!
//! ## Concurrent threads access
//! ### Single file single mapping parallel read
//! ```
//! ```
//!
//! ### Single file multiple mappings parallel read
//! ```
//! ```
//!
//! ### Multiple files multiple mappings parallel read
//! ```
//! ```
//!
//! ### Multiple writers race condition detector
//! ```
//! ```
//!
//! ## Legal
//! ### Author
//!
//! Vladimir Voznesenskiy <vvoznesensky@yandex.ru>
//!
//! ### License
//! Apache License v2.0*/

#![feature(allocator_api, pointer_byte_offsets, btree_cursors, concat_bytes,
    ptr_from_ref, const_mut_refs)]

use ctor;
use const_str;
use errno::{errno};
use libc;
use libc::{c_int, c_void};
use nix::sys::signal::{
    sigaction, SigAction, SigHandler, SaFlags, SigSet, Signal};
use std::alloc;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::marker;
use std::ops;
use std::ptr;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard, Mutex, Arc};

// Panic on file problems.
macro_rules! panic_syserr {
    ( $rval:expr ) => { {
        let rval = unsafe { $rval };
        if rval as isize == -1 {
            let e = errno();
            panic!("System error #{}: {}", e.0, e);
        }
        rval
    } }
}

////////////////////////////////////////////////////////////////////////////////
// FileHolder: RAII fixture to handle raw files
#[derive(Debug)]
struct FileHolder(c_int);
macro_rules! libc_result {
    ( $rval:expr ) => { {
        let r = unsafe { $rval };
        if r as isize == -1 { Err(std::io::Error::last_os_error()) }
        else { Ok(r) }
    } }
}
impl FileHolder{
    fn new(prefix: &str, extension: &str) -> std::io::Result<Self> {
        let fname = std::format!("{}.{}\0", prefix, extension);
        let r = libc_result!(libc::open(fname.as_ptr() as *const i8,
                                        libc::O_CREAT|libc::O_RDWR, 0o666))?;
        Ok(Self(r))
    }
    fn read_header_of_header(&self) -> Option<HeaderOfHeader> {
        let mut h = std::mem::MaybeUninit::<HeaderOfHeader>::uninit();
        const S: usize = std::mem::size_of::<HeaderOfHeader>();
        let read = panic_syserr!(libc::read(self.0,
                                core::ptr::from_mut(&mut h) as *mut c_void, S));
        if read == S as isize { Some(unsafe{h.assume_init()}) } else { None }
    }
}
impl std::ops::Deref for FileHolder {
    type Target = c_int;
    fn deref(&self) -> &c_int { &self.0 }
}
impl Drop for FileHolder {
    fn drop(&mut self) {
        panic_syserr!(libc::close(self.0));
    }
}

////////////////////////////////////////////////////////////////////////////////
// MapHolder: RAII fixture to handle file memory mapping
#[derive(Debug)]
struct MapHolder(*mut c_void, usize);
impl MapHolder {
    fn new(fd: c_int, aa: *mut c_void, size: usize) -> std::io::Result<Self> {
        let mfn = if aa.is_null() {0} else {libc::MAP_FIXED_NOREPLACE};
        //let f = libc::MAP_SHARED_VALIDATE | mfn;
        let f = libc::MAP_SHARED | mfn;
        let a = libc_result!(libc::mmap(aa, size, libc::PROT_READ, f, fd, 0))?;
        Ok(Self(a, size))
    }
}
impl Drop for MapHolder {
    fn drop(&mut self) {
        panic_syserr!(libc::munmap(self.0, self.1));
    }
}

////////////////////////////////////////////////////////////////////////////////
/// Arena: internal structure to hold all the file and mapping stuff.
/// Created by Holder instance and shared by all it's clones in all threads.
#[derive(Debug)]
struct Arena {
    mem: MapHolder,
    fd: FileHolder,     // Main file, mapped onto mem.
    log_fd: FileHolder, // Log file, consists of pairs (u32 page #, page).
    readers: Mutex<u32>, // Number of readers to apply and revoke flock once.
    page_size: usize,
}

////////////////////////////////////////////////////////////////////////////////
/// Auxilliary constants
/// Ki, kibi
pub const KI: usize = 1024;
/// Mi, mebi
pub const MI: usize = 1024 * KI;
/// Gi, gibi
pub const GI: usize = 1024 * MI;
/// Ti, tebi
pub const TI: usize = 1024 * GI;

////////////////////////////////////////////////////////////////////////////////
/// Holder: RAII fixture to initialize the storage files and mmapping
///
/// Shares file mapped memory allocation arena with all it's clones.
///
/// Do not mess up with the Root type: this crate cannot figure out if the type
/// of root object has been changed someway.
#[derive(Debug, Clone)]
pub struct Holder<'a, Root: 'a + Default> {
    arena: Arc<RwLock<Arena>>,
    phantom: marker::PhantomData<&'a Root>
}

/// Error: all possible errors of [Holder] and arena initialization
#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    WrongFileType,
    WrongMajorVersion,
    WrongEndianBitness,
    WrongMagick,
    WrongAddress,
    WrongSize,
}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self { Self::IoError(value) }
}

/// [Holder::new] initialization result
pub type Result<T> = std::result::Result<T, Error>;

impl<'a, Root: 'a + Default> Holder<'a, Root> {
    /// Initialize arena and it's [Holder]
    ///
    /// `file_pfx` - main (`.odb`) and log (`.log`) files path prefix.
    ///
    /// `arena_address` - optional address of arena space beginning. Useful for
    ///     initialization of rare multi-arenas multi-code combinations. Most
    ///     users are sufficient to pass `None`.
    ///
    /// `arena_size` - size of arena address space. Can grow, but cannot shrink.
    ///
    /// `magick` - user-defined magick number to distinguish among different
    ///     versions of stored structures (i.e. schema). Dangerous to mess.
    pub fn new(file_pfx: &str, arena_address: Option<usize>,
                    arena_size: usize, magick: u64) -> Result<Self> {
        let ps = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
        assert!(ps > 0);
        let page_size = ps as usize;
        assert!(page_size.is_power_of_two());
        let fd = FileHolder::new(file_pfx, "odb")?;
        flock_w(*fd);
        let h = fd.read_header_of_header();
        let ld = FileHolder::new(file_pfx, "log")?;
        let aa = match arena_address {
            None => match h { None => 0, Some(ha) => ha.address, },
            Some(a) => match h {
                None => a,
                Some(ha) => if a == ha.address { a }
                            else { return Err(Error::WrongAddress) }
            }
        } as *mut c_void;
        let addr = MapHolder::new(*fd, aa, arena_size)?;
        let shown = addr.0 as usize;
        let arena = Arena {
            mem: addr,
            fd: fd,
            log_fd: ld,
            readers: Mutex::new(0),
            page_size: page_size,
        };
        let arena = Arc::new(RwLock::new(arena));
        let s = Self { arena: arena, phantom: marker::PhantomData };
        prep_header(&s, magick, shown, arena_size)?;
        Ok(s)
    }
    /// Shared-lock the storage and get [Reader] smart pointer to Root instance
    pub fn read(&self) -> Reader::<Root> {
        let guard = self.arena.read().unwrap();
        {
            let mut readers = guard.readers.lock().unwrap();
            if *readers == 0 { flock_r(*guard.fd); }
            *readers += 1;
        }
        Reader::<Root> {
            guard: guard,
            arena: Arc::clone(&self.arena),
            phantom: marker::PhantomData,
        }
    }
    fn internal_write<const PAGES_WRITABLE: bool>(&self) ->
            InternalWriter<Root, PAGES_WRITABLE> {
        let guard = self.arena.write().unwrap();
        flock_w(*guard.fd);
        let rv = InternalWriter::<Root, PAGES_WRITABLE> {
            guard: guard,
            //_arena: Arc::clone(&self.arena),
            phantom: marker::PhantomData,
        };
        rv.setseg();
        rv
    }
    pub fn write(&mut self) -> Writer<Root> { self.internal_write::<true>() }

    /// Returns the numeric address of the arena space beginning
    pub fn address(&self) -> usize {
        self.arena.read().unwrap().mem.0 as usize
    }

    /// Returns the size of the arena address space
    pub fn size(&self) -> usize {
        self.arena.read().unwrap().mem.1 as usize
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        flock_w(*self.fd);
        rollback::<true>(*self.fd, *self.log_fd, self.mem.0, self.page_size);
        unflock(*self.fd);
    }
}

////////////////////////////////////////////////////////////////////////////////
// Very internal functions that does not know about Arena structure, but
// only manipulates fds and mapped memory.

// Internal rollback.
// Must be called for flock-ed fd in LOCK_EX mode and guaranteed exclusive
// access of mem for this thread among threads that have access to this fd.
// For further use in Holder and Writer.
fn rollback<const PAGES_WRITABLE: bool>(fd: c_int, lfd: c_int,
            mem: *mut c_void, page_size: usize) {
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
    let mut page_no: u32 = 0; // 0 for suppressing compilation error
    let pgn_ptr = (&mut page_no as *mut u32) as *mut c_void;
    while read_exactly(lfd, pgn_ptr, 4)
            == 4 {
        let offset = (page_no as usize) * page_size;
        let addr = unsafe{mem.byte_add(offset)};
        if !PAGES_WRITABLE {
            panic_syserr!(libc::mprotect(addr, page_size, libc::PROT_WRITE));
        }
        read_exactly(lfd, addr, page_size);
        panic_syserr!(libc::mprotect(addr, page_size, libc::PROT_READ));
    }
    sync(fd);
    truncate(lfd);
}

// Internal commit.
// Must be called for flock-ed fd in LOCK_EX mode and guaranteed exclusive
// access of mem for this thread among threads that have access to this fd.
// For further use in WriterAccessor.
fn commit(fd: c_int, lfd: c_int, mem: *mut c_void, size: libc::size_t) {
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
    panic_syserr!(libc::mprotect(mem, size, libc::PROT_READ));
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
    sync(fd);
    truncate(lfd);
}

// Read exactly count bytes or end from the file.
fn read_exactly(lfd: c_int, buf: *mut c_void, count: libc::size_t) -> usize { 
    let mut s: usize;
    let mut rval: usize = 0;
    let mut c = count;
    while c > 0 && {
            s = panic_syserr!(libc::read(lfd, buf, c)) as usize;
            s != 0} {
        rval += s;
        c -= s;
    }
    rval
}

// Making log file ready for the next transaction.
fn truncate(lfd: c_int) {
    panic_syserr!(libc::ftruncate(lfd, 0));
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
}

// File sync
fn sync(lfd: c_int) {
    panic_syserr!(libc::fdatasync(lfd));
}

// Flock the main file.
fn flock_w(fd: c_int) {
    panic_syserr!(libc::flock(fd, libc::LOCK_EX));
}
fn flock_r(fd: c_int) {
    panic_syserr!(libc::flock(fd, libc::LOCK_SH));
}
fn unflock(fd: c_int) {
    panic_syserr!(libc::flock(fd, libc::LOCK_UN));
}

// Currently the simpliest bump allocator.
fn allocate(from_size: (*const u8, usize), layout: alloc::Layout) ->
        std::result::Result<ptr::NonNull<[u8]>, alloc::AllocError> {
    let h = unsafe{(from_size.0 as *mut HeaderOfHeader).as_mut()}.unwrap();
    let na = unsafe{from_size.0.add(h.current)};
    let s = na.align_offset(layout.align()) + layout.size();
    h.current += s;
    if h.current > from_size.1 {
        return Err(alloc::AllocError)
    } else {
        return Ok(ptr::NonNull::slice_from_raw_parts(
                                ptr::NonNull::new(na.cast_mut()).unwrap(), s))
    }
}

unsafe fn deallocate(_from_size: (*const u8, usize), _ptr: ptr::NonNull<u8>,
                     _layout: alloc::Layout) {}

////////////////////////////////////////////////////////////////////////////////
// SIGSEGV on write to read-only page and it's handler memory map
impl<Root, const PAGES_WRITABLE: bool>
        InternalWriter<'_, Root, PAGES_WRITABLE> {
    fn setseg(&self) {
        let g = &self.guard;
        let s = g.mem.1;
        let b = g.mem.0 as *const c_void;
        let e = unsafe{b.byte_add(s)};
        MEM_MAP.with_borrow_mut(|mb| {
            let mut c = mb.upper_bound(ops::Bound::Included(&b));
            if let Some((l, ta)) = c.key_value() {
                assert!(unsafe{l.byte_add(ta.size)} <= b);
                c.move_next();
                if let Some((l, _)) = c.key_value() { assert!(*l >= e); }
            }
            mb.insert(b, ThreadArena{ size: s, odb_fd: *g.fd,
                                    log_fd: *g.log_fd, page_size: g.page_size});
        });
    }

    fn remseg(&self) {
        let g = &self.guard;
        let b = g.mem.0 as *const c_void;
        MEM_MAP.with_borrow_mut(|mb| {
            let r = mb.remove(&b).unwrap();
            assert_eq!(r, ThreadArena{ size: g.mem.1, odb_fd: *g.fd,
                                    log_fd: *g.log_fd, page_size: g.page_size});
        });
    }
}

fn save_old_page(mem: *const c_void, size: usize, log_fd: c_int,
                                        page_size: usize, addr: *const c_void) {
    let offset = addr.align_offset(page_size) as isize;
    let begin = unsafe{ addr.byte_offset(offset - (page_size) as isize) };
    assert_eq!(begin.align_offset(page_size), 0);
    assert!(begin >= mem);
    let pn = unsafe{ begin.byte_offset_from(mem) } / (page_size as isize);
    let page_no: u32 = u32::try_from(pn).unwrap();
    assert!(size / page_size > (page_no as usize));
    // XXX use writev
    panic_syserr!(libc::write(log_fd,
            std::ptr::from_ref::<u32>(&page_no) as *const c_void, 4));
    panic_syserr!(libc::write(log_fd, begin, page_size));
    sync(log_fd);
    panic_syserr!(libc::mprotect(begin as *mut c_void, page_size,
                                            libc::PROT_READ|libc::PROT_WRITE));
}

const EXTEND_BYTES: usize = 8;

fn extend_file(mem: *const c_void, size: usize, odb_fd: c_int,
                                        page_size: usize, addr: *const c_void) {
    let past_addr = unsafe { addr.byte_add(EXTEND_BYTES) };
    let offset = past_addr.align_offset(page_size);
    let e = unsafe { past_addr.byte_add(offset) };
    let offset = unsafe { e.byte_offset_from(mem) };
    assert!(usize::try_from(offset).unwrap() <= size);
    panic_syserr!(libc::ftruncate(odb_fd, offset as libc::off_t));
}

extern "C" fn sighandler(signum: c_int, info: *mut libc::siginfo_t,
                            ucontext: *mut c_void) {
    let addr = unsafe{info.as_ref().unwrap().si_addr()} as *const c_void;
    if MEM_MAP.with_borrow(|mb| {
        let c = mb.upper_bound(ops::Bound::Included(&addr));
        if let Some((l, ta)) = c.key_value() {
            if addr < unsafe{l.byte_add(ta.size)} {
                if signum == libc::SIGSEGV {
                    save_old_page(*l, ta.size, ta.log_fd, ta.page_size, addr);
                } else {
                    assert!(signum == libc::SIGBUS);
                    extend_file(*l, ta.size, ta.odb_fd, ta.page_size, addr);
                }
                true
            } else { false }
        } else { false }
    }) { return };
    let oa = if signum == libc::SIGSEGV {
            unsafe { OLDACTSEGV.unwrap() }
        } else {
            assert_eq!(signum, libc::SIGBUS);
            unsafe { OLDACTBUS.unwrap() }
        };
    if !oa.mask().contains(Signal::try_from(signum).unwrap()) {
        match oa.handler() {
            SigHandler::SigDfl => { 
                panic_syserr!(libc::kill(libc::getpid(), libc::SIGABRT));
            },
            SigHandler::SigIgn => (),
            SigHandler::Handler(f) => f(signum),
            SigHandler::SigAction(f) => f(signum, info, ucontext),
        }
    }
}

#[derive(PartialEq, Debug)]
struct ThreadArena {
    size: usize,
    odb_fd: c_int,
    log_fd: c_int,
    page_size: usize,
}
thread_local! {
    static MEM_MAP: RefCell<BTreeMap<*const c_void, ThreadArena>> =
        const { RefCell::new(BTreeMap::new()) };
}

// Sigaction stuff: signal handler, install/remove it on crate load/remove.
static mut OLDACTSEGV: Option<SigAction> = None;
static mut OLDACTBUS: Option<SigAction> = None;

#[ctor::ctor]
fn initialise_sigs() {
    assert_eq!(unsafe{OLDACTSEGV}, None);
    assert_eq!(unsafe{OLDACTBUS}, None);
    let act = SigAction::new(SigHandler::SigAction(sighandler),
               SaFlags::SA_RESTART.union(SaFlags::SA_SIGINFO), SigSet::empty());
    unsafe { OLDACTBUS = Some(sigaction(Signal::SIGBUS, &act).unwrap()); }
    unsafe { OLDACTSEGV = Some(sigaction(Signal::SIGSEGV, &act).unwrap()); }
}

fn finalise_sig(s: Signal, osa: &mut Option<SigAction>) {
    unsafe{
        sigaction(s, &osa.unwrap()).unwrap();
        *osa = None;
    }
}

#[ctor::dtor]
fn finalise_sigs() {
    finalise_sig(Signal::SIGSEGV, &mut unsafe{OLDACTSEGV});
    finalise_sig(Signal::SIGBUS, &mut unsafe{OLDACTBUS});
}

////////////////////////////////////////////////////////////////////////////////
// Header stored in file
#[repr(C, align(8))]
struct HeaderOfHeader {
    filetype: [u8; 8],  // Letters to show the file type "TMFALLOC"
    version: [u8; 8],   // Crate major version
    endian_bitness: u64,// Number of bits and on what end they start
    magick: u64,        // Error prone fixture to check the user types version
    address: usize,     // Base address of mapping to check
    size: usize,        // Size of mapping to check
    current: usize,     // Next piece of the bump allocator
}
#[repr(C, align(8))]
struct Header<Root: Default> {
    h: HeaderOfHeader,
    root: Root,
}

// Check if the memory map header is ok.
// If empty, then prepare and commit, otherwise rollback.
fn prep_header<'a, Root: Default>(holder: &Holder::<'a, Root>,
        magick: u64, address: usize, size: usize) -> Result<()> {
    let w = &holder.internal_write::<false>().guard;
    let header_state = header_is_ok_state(magick, address, size)?;
    let ptr = unsafe{(address as *mut Header<Root>).as_mut()}.unwrap();
    match header_state {
        HeaderState::Fine => {} ,
        HeaderState::NeedsToGrow => {
            ptr.h.size = size;
            commit(*w.fd, *w.log_fd, w.mem.0, w.mem.1);
        }
        HeaderState::Empty => {
            *ptr = Header::<Root> {
                h: HeaderOfHeader {
                    filetype: FILETYPE,
                    version: VERSION,
                    endian_bitness: ENDIAN_BITNESS,
                    magick: magick,
                    address: address,
                    size: size,
                    current: std::mem::size_of::<Header<Root>>(),
                },
                root: Default::default()
            };
            commit(*w.fd, *w.log_fd, w.mem.0, w.mem.1);
        }
    }
    Ok(())
}
const FILETYPE: [u8; 8] = const_str::to_byte_array!(b"TMFALLOC");
const V: &str = env!("CARGO_PKG_VERSION_MAJOR");
const V_PREF: &str = const_str::repeat!(" ", 8 - V.len());
const V_STR: &str = const_str::concat!(V_PREF, V);
const VERSION: [u8; 8] = const_str::to_byte_array!(V_STR);
const ENDIAN_BITNESS: u64 = std::mem::size_of::<usize>() as u64;
enum HeaderState { Empty, NeedsToGrow, Fine }
fn header_is_ok_state(magick: u64, address: usize,
                        size: usize) -> Result<HeaderState> {
    let ptr = unsafe{(address as *const HeaderOfHeader).as_ref()}.unwrap();
    if ptr.filetype == [0,0,0,0,0,0,0,0] && ptr.magick == 0 && ptr.address == 0
            && ptr.current == 0 {
        Ok(HeaderState::Empty)
    } else if ptr.filetype != FILETYPE {
        Err(Error::WrongFileType)
    } else if ptr.version != VERSION {
        Err(Error::WrongMajorVersion)
    } else if ptr.endian_bitness != ENDIAN_BITNESS {
        Err(Error::WrongEndianBitness)
    } else if ptr.magick != magick {
        Err(Error::WrongMagick)
    } else if ptr.address != address {
        Err(Error::WrongAddress)
    } else if ptr.size > size {
        Err(Error::WrongSize)
    } else if ptr.size < size {
        Ok(HeaderState::NeedsToGrow)
    } else { Ok(HeaderState::Fine) }
}

////////////////////////////////////////////////////////////////////////////////
/// Reader: a smart pointer allowing storage concurrent read access
///
/// Can be created by [Holder::read] method. Holds shared locks to the memory
/// mapped file storage until dropped. Provides shared read access to Root
/// persistent instance.
pub struct Reader<'a, Root: Default> {
    guard: RwLockReadGuard<'a, Arena>,
    arena: Arc<RwLock<Arena>>,
    phantom: marker::PhantomData<&'a Root>
}
impl<Root: Default> ops::Deref for Reader<'_, Root> {
    type Target = Root;
    fn deref(&self) -> &Root {
        &unsafe{(self.guard.mem.0 as *const Header<Root>).as_ref()}
                                                                .unwrap().root
    }
}
impl<Root: Default> Drop for Reader<'_, Root> {
    fn drop(&mut self) {
        let arena = self.arena.read().unwrap();
        let mut readers = arena.readers.lock().unwrap();
        if *readers == 1 { unflock(*arena.fd); }
        assert!(*readers > 0);
        *readers -= 1;
    }
}

////////////////////////////////////////////////////////////////////////////////
// Writer accessor to allow storage exclusive write access.
/// InternalWriter: a smart pointer allowing storage exclusive write access
///
/// Not indended for direct creation by a user. See [Writer].
pub struct InternalWriter<'a, Root, const PAGES_WRITABLE: bool> {
    guard: RwLockWriteGuard<'a, Arena>,
    //_arena: Arc<RwLock<Arena>>,
    phantom: marker::PhantomData<&'a Root>
}
impl<'a, Root, const PAGES_WRITABLE: bool>
        InternalWriter<'a, Root, PAGES_WRITABLE> {
    pub fn rollback(&self) {
        let g = &self.guard;
        rollback::<PAGES_WRITABLE>(*g.fd, *g.log_fd, g.mem.0, g.mem.1);
    }
    pub fn commit(&self) {
        let g = &self.guard;
        commit(*g.fd, *g.log_fd, g.mem.0, g.mem.1);
    }
}
impl<Root: Default, const PAGES_WRITABLE: bool> ops::Deref
        for InternalWriter<'_, Root, PAGES_WRITABLE> {
    type Target = Root;
    fn deref(&self) -> &Root {
        &unsafe{(self.guard.mem.0 as *const Header<Root>).as_ref()}
            .unwrap().root
    }
}
impl<Root: Default, const PAGES_WRITABLE: bool> ops::DerefMut
        for InternalWriter<'_, Root, PAGES_WRITABLE> {
    fn deref_mut(&mut self) -> &mut Root {
        &mut unsafe{(self.guard.mem.0 as *mut Header<Root>).as_mut()}
            .unwrap().root
    }
}
impl<Root, const PAGES_WRITABLE: bool> Drop
        for InternalWriter<'_, Root, PAGES_WRITABLE> {
    fn drop(&mut self) {
        let a = &self.guard;
        rollback::<PAGES_WRITABLE>(*a.fd, *a.log_fd, a.mem.0, a.mem.1);
        self.remseg();
        unflock(*a.fd);
    }
}

/// Writer: a smart pointer allowing storage exclusive write access
///
/// Can be created by [Holder::write] method. Holds exclusive locks to the
/// memory mapped file storage until dropped. Provides exclusive write access to
/// Root persistent instance.
pub type Writer<'a, Root> = InternalWriter<'a, Root, true>;

////////////////////////////////////////////////////////////////////////////////
/// Allocator applicable for standard containers to make them persistent
///
/// Create [Writer] by [Holder::write] in the same thread before allocation,
/// deallocation and other persistent storage update.
pub struct Allocator;

impl Allocator {
    // Find the applicable memory segment for the given allocator
    fn segment(&self) -> (*const u8, usize) {
        let a = (self as *const Allocator) as *const c_void;
        MEM_MAP.with_borrow(|mb| {
            let c = mb.upper_bound(ops::Bound::Included(&a));
            match c.key_value() {
                None => panic!("No arena found for address {:X}", a as usize),
                Some((l, ta)) => {
                    assert!(*l < a); // Internal crate error
                    let u = unsafe { l.byte_add(ta.size) };
                    assert!(a <= u); // May be crate user's failure
                    (*l as *const u8, ta.size as usize)
                }
            }
        })
    }
}

unsafe impl alloc::Allocator for Allocator {
    fn allocate(&self, layout: alloc::Layout) ->
            std::result::Result<ptr::NonNull<[u8]>, alloc::AllocError> {
        allocate(self.segment(), layout)
    }
    unsafe fn deallocate(&self, p: ptr::NonNull<u8>, layout: alloc::Layout) {
        deallocate(self.segment(), p, layout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct S(u64);

    #[test]
    fn it_works() {
        let mut h1 = Holder::<S>::new("1234567890abcdef", Some(0x70ffefe00000),
                                          TI, 0x1234567890abcdef).unwrap();
        let mut w = h1.write();
        w.0 = 31415926;

        w.commit();
        drop(w);
        drop(h1);

        let h2 = Holder::<S>::new("1234567890abcdef", None,
                                          TI, 0x1234567890abcdef).unwrap();
        let r = h2.read();
        assert_eq!(r.0, 31415926);
    }
}

