//! # TMFAlloc: Transactional Mapped File Allocator for Rust
//!
//! ## Storage initialization
//! ```
//! # let _ = std::fs::remove_file("test1.odb");
//! # let _ = std::fs::remove_file("test1.log");
//! # #[cfg(target_pointer_width = "64")]
//! # const ADDRESS: usize = 0x70ffe6100000;
//! # #[cfg(target_pointer_width = "32")]
//! # const ADDRESS: usize = 0xb6100000;
//! ##[derive(Debug)]
//! struct S { /* some fields */ };
//! let h = unsafe {
//!     tmfalloc::Holder::<S>::open("test1", Some(ADDRESS), tmfalloc::MI,
//!                 0xfedcab0987654321, |a| { S{ /* ... */ } }) }.unwrap();
//! // Detects memory areas overlapping:
//! match unsafe { tmfalloc::Holder::<S>::open("test1", None, tmfalloc::MI,
//!                 0xfedcab0987654321, |a| { panic!("!") }) }.unwrap_err() {
//!     tmfalloc::Error::IoError(e) => {
//!         assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists) },
//!     _ => panic!("Wrong type of error")
//! }
//! # drop(h);
//! # let _ = std::fs::remove_file("test1.odb");
//! # let _ = std::fs::remove_file("test1.log");
//! ```
//!
//! ## Commited data in storage becomes persistent
//! ```
//! # let _ = std::fs::remove_file("test2.odb");
//! # let _ = std::fs::remove_file("test2.log");
//! # #[cfg(target_pointer_width = "64")]
//! # const ADDRESS: usize = 0x70ffe6200000;
//! # #[cfg(target_pointer_width = "32")]
//! # const ADDRESS: usize = 0xb6200000;
//! struct S(u64);
//! let mut h1 = unsafe {
//!     tmfalloc::Holder::<S>::open("test2", Some(ADDRESS), tmfalloc::MI,
//!                     0x1234567890abcdef, |a| { S(2718281828) }) }.unwrap();
//! let mut w = h1.write();
//! w.0 = 31415926;
//!
//! w.commit();
//! assert_eq!(w.0, 31415926);
//! drop(w);
//! drop(h1);
//!
//! let h2 = unsafe {
//!     tmfalloc::Holder::<S>::open("test2", None, tmfalloc::MI,
//!                     0x1234567890abcdef, |a| { panic!("!")} ) }.unwrap();
//! let r = h2.read();
//! assert_eq!(r.0, 31415926);
//! assert_eq!(h2.address(), ADDRESS);
//! assert_eq!(h2.size(), tmfalloc::MI);
//! # drop(r);
//! # drop(h2);
//! # let _ = std::fs::remove_file("test2.odb");
//! # let _ = std::fs::remove_file("test2.log");
//! ```
//!
//! ## Data changes can be rolled back
//! ### Explicitly
//! ```
//! # let _ = std::fs::remove_file("test3.odb");
//! # let _ = std::fs::remove_file("test3.log");
//! # #[cfg(target_pointer_width = "64")]
//! # const ADDRESS: usize = 0x70ffe6300000;
//! # #[cfg(target_pointer_width = "32")]
//! # const ADDRESS: usize = 0xb6300000;
//! # struct S(u64);
//! # let mut h1 = unsafe {
//! #    tmfalloc::Holder::<S>::open("test3", Some(ADDRESS), tmfalloc::MI,
//! #                   0x1234567890abcdef, |a| { S(2718281828) }) }.unwrap();
//! # let mut w = h1.write();
//! // --snip--
//! w.0 = 31415926;
//!
//! w.rollback();
//! assert_eq!(w.0, 2718281828);
//! // --snip--
//! # drop(w);
//! # drop(h1);
//! # let h2 = unsafe {
//! #   tmfalloc::Holder::<S>::open("test3", None, tmfalloc::MI,
//! #                   0x1234567890abcdef, |a| { panic!("!") }) }.unwrap();
//! let r = h2.read();
//! assert_eq!(r.0, 2718281828);
//! # drop(r);
//! # drop(h2);
//! # let _ = std::fs::remove_file("test3.odb");
//! # let _ = std::fs::remove_file("test3.log");
//! ```
//!
//! ### Implicitly
//! ```
//! # let _ = std::fs::remove_file("test4.odb");
//! # let _ = std::fs::remove_file("test4.log");
//! # #[cfg(target_pointer_width = "64")]
//! # const ADDRESS: usize = 0x70ffe6400000;
//! # #[cfg(target_pointer_width = "32")]
//! # const ADDRESS: usize = 0xb6400000;
//! # struct S(u64);
//! # let mut h1 = unsafe {
//! #   tmfalloc::Holder::<S>::open("test4", Some(ADDRESS), tmfalloc::MI,
//! #                   0x1234567890abcdef, |a| { S(2718281828) }) }.unwrap();
//! # let mut w = h1.write();
//! // --snip--
//! w.0 = 31415926;
//!
//! assert_eq!(w.0, 31415926);
//! drop(w);
//! drop(h1);
//! // --snip--
//! # let h2 = unsafe {
//! #   tmfalloc::Holder::<S>::open("test4", None, tmfalloc::MI,
//! #                   0x1234567890abcdef, |a| {panic!("!") }) }.unwrap();
//! let r = h2.read();
//! assert_eq!(r.0, 2718281828);
//! # drop(r);
//! # drop(h2);
//! # let _ = std::fs::remove_file("test4.odb");
//! # let _ = std::fs::remove_file("test4.log");
//! ```
//!
//! ## Allocator makes standard collections persistent
//! ```
//! ##![feature(allocator_api, btreemap_alloc)]
//! # let _ = std::fs::remove_file("test5.odb");
//! # let _ = std::fs::remove_file("test5.log");
//! # #[cfg(target_pointer_width = "64")]
//! # const ADDRESS: usize = 0x70ffe6500000;
//! # #[cfg(target_pointer_width = "32")]
//! # const ADDRESS: usize = 0xb6500000;
//! type A = tmfalloc::Allocator;
//! type V = std::vec::Vec<u8, A>;
//! struct S {
//!     v: V,
//!     b: std::boxed::Box<usize, A>,
//!     m: std::collections::BTreeMap<V, usize, A>,
//!     s: std::collections::BTreeSet<usize, A>,
//! }
//! impl S { fn new(a: tmfalloc::Allocator) -> S {
//!     S {
//!         v: V::new_in(a.clone()),
//!         b: std::boxed::Box::<usize, A>::new_in(0, a.clone()),
//!         m: std::collections::BTreeMap::<V, usize, A>::new_in(a.clone()),
//!         s: std::collections::BTreeSet::<usize, A>::new_in(a),
//!     }
//! } }
//! let mut h1 = unsafe {
//!     tmfalloc::Holder::<S>::open("test5", Some(ADDRESS), tmfalloc::MI,
//!                     0xfedcba9876543210, S::new) }.unwrap();
//! let mut w = h1.write();
//! let a: A = w.allocator();
//! w.v.extend_from_slice(b"Once upon a time...");
//! w.b = Box::new_in(12345, a.clone());
//! w.m.insert("Fyodor Dostoevsky".as_bytes().to_vec_in(a.clone()), 59);
//! w.m.insert("Leo Tolstoy".as_bytes().to_vec_in(a.clone()), 82);
//! w.m.insert("Anton Chekhov".as_bytes().to_vec_in(a.clone()), 44);
//! w.m.insert("Vladimir Nabokov".as_bytes().to_vec_in(a), 78);
//! for i in [13, 11, 7, 5, 3, 2, 1] { w.s.insert(i); } ;
//! w.commit();
//! drop(w);
//! drop(h1);
//!
//! let h2 = unsafe {
//!     tmfalloc::Holder::<S>::open("test5", None, tmfalloc::MI,
//!                     0xfedcba9876543210, |a| {panic!("!")}) }.unwrap();
//! let r = h2.read();
//! assert_eq!(r.v, b"Once upon a time...");
//! assert_eq!(*r.b, 12345);
//! assert_eq!(std::str::from_utf8(r.m.first_key_value().unwrap().0),
//!                                                     Ok("Anton Chekhov"));
//! assert_eq!(std::str::from_utf8(r.m.last_key_value().unwrap().0),
//!                                                     Ok("Vladimir Nabokov"));
//! let mut i = r.s.iter();
//! for j in [1usize, 2, 3, 5, 7, 11, 13] {
//!     assert_eq!(Some(&j), i.next());
//! }
//! assert_eq!(None, i.next());
//! # drop(r);
//! # drop(h2);
//! # let _ = std::fs::remove_file("test5.odb");
//! # let _ = std::fs::remove_file("test5.log");
//! ```
//!
//! ## Data could be deallocated to reuse the memory
//! ```
//! ##![feature(allocator_api)]
//! # let _ = std::fs::remove_file("test6.odb");
//! # let _ = std::fs::remove_file("test6.log");
//! # #[cfg(target_pointer_width = "64")]
//! # const ADDRESS: usize = 0x70ffe6600000;
//! # #[cfg(target_pointer_width = "32")]
//! # const ADDRESS: usize = 0xb6600000;
//! type V = std::vec::Vec<u8, tmfalloc::Allocator>;
//! let mut h = unsafe {
//!     tmfalloc::Holder::<V>::open("test6", Some(ADDRESS), tmfalloc::MI,
//!                     0xfedcba9876543210, |a| { V::new_in(a) }) }.unwrap();
//! let mut w = h.write();
//! w.extend_from_slice(b"Once upon a time...");
//! let address1 = w.as_ptr();
//! w.commit();
//! drop(w);
//!
//! let mut w = h.write();
//! w.clear();
//! w.shrink_to_fit();
//! w.extend_from_slice(b"Twice upon a time...");
//! let address2 = w.as_ptr();
//! w.commit();
//! assert_eq!(address1, address2);
//! # drop(w);
//! # drop(h);
//! # let _ = std::fs::remove_file("test6.odb");
//! # let _ = std::fs::remove_file("test6.log");
//! ```
//!
//! ## Storage can be expanded, but not trimmed
//! ```
//! ##![feature(allocator_api)]
//! # let _ = std::fs::remove_file("test7.odb");
//! # let _ = std::fs::remove_file("test7.log");
//! # #[cfg(target_pointer_width = "64")]
//! # const ADDRESS: usize = 0x70ffe6700000;
//! # #[cfg(target_pointer_width = "64")]
//! # const SIZE: usize = 5 * tmfalloc::GI;
//! # #[cfg(target_pointer_width = "32")]
//! # const ADDRESS: usize = 0xb6700000;
//! # #[cfg(target_pointer_width = "32")]
//! # const SIZE: usize = 5 * tmfalloc::MI;
//! type V = std::vec::Vec<u8, tmfalloc::Allocator>;
//! let mut h = unsafe {
//!     tmfalloc::Holder::<V>::open("test7", Some(ADDRESS), SIZE,
//!                     0xfedcba9876543210, |a| { V::new_in(a) }) }.unwrap();
//! let mut w = h.write();
//! w.extend_from_slice(&[b'.'; tmfalloc::MI - 2 * tmfalloc::KI]);
//! w.commit();
//! drop(w);
//! drop(h);
//! let mut h = unsafe {
//!     tmfalloc::Holder::<V>::open("test7", None, 2 * SIZE,
//!                     0xfedcba9876543210, |a| { panic!("!") }) }.unwrap();
//! let mut w = h.write();
//! w.extend_from_slice(&[b'.'; tmfalloc::MI]);
//! w.commit();
//! w.clear();
//! w.shrink_to_fit();
//! w.commit();
//! drop(w);
//! drop(h);
//! match unsafe {
//!         tmfalloc::Holder::<V>::open("test7", None, SIZE,
//!             0xfedcba9876543210, |a| { panic!("!") }) }.unwrap_err() {
//!     tmfalloc::Error::WrongSize => {},
//!     _ => panic!("Wrong type of error")
//! }
//! # let _ = std::fs::remove_file("test7.odb");
//! # let _ = std::fs::remove_file("test7.log");
//! ```
//!
//! ## Same storage can be used in several threads
//! ```
//! ##![feature(allocator_api)]
//! # let _ = std::fs::remove_file("test8.odb");
//! # let _ = std::fs::remove_file("test8.log");
//! # #[cfg(target_pointer_width = "64")]
//! # const ADDRESS: usize = 0x70ffe6800000;
//! # #[cfg(target_pointer_width = "64")]
//! # const SIZE: usize = 5 * tmfalloc::GI;
//! # #[cfg(target_pointer_width = "32")]
//! # const ADDRESS: usize = 0xb6800000;
//! # #[cfg(target_pointer_width = "32")]
//! # const SIZE: usize = 5 * tmfalloc::MI;
//! let mut h0 = unsafe {
//!     tmfalloc::Holder::<char>::open("test8", Some(ADDRESS), SIZE,
//!                     0xabcdef9876543210, |a| { '.' }) }.unwrap();
//! use std::{thread, time};
//! let mut h1 = h0.clone();
//! thread::spawn(move || {
//!     let mut w = h1.write();
//!     *w = '!';
//!     w.commit();
//! }).join().expect("The thread has panicked");
//! let mut h2 = h0.clone();
//! let mut w = h0.write();
//! assert_eq!(*w, '!');
//! *w = '.';
//! let t = thread::spawn(move || {
//!     let mut w = h2.write();
//!     *w = '?';
//!     w.commit();
//! });
//! thread::sleep(time::Duration::from_millis(1));
//! assert_eq!(*w, '.');
//! drop(w);
//! t.join().expect("The thread has panicked");
//! let mut h3 = h0.clone();
//! let mut r = h0.read();
//! thread::spawn(move || {
//!     let mut r = h3.read();
//!     assert_eq!(*r, '?');
//! }).join().expect("The thread has panicked");
//! assert_eq!(*r, '?');
//! # let _ = std::fs::remove_file("test8.odb");
//! # let _ = std::fs::remove_file("test8.log");
//! ```

#![feature(
    allocator_api,
    btree_cursors,
    concat_bytes,
    const_mut_refs,
    alloc_layout_extra,
    slice_ptr_get,
    btreemap_alloc,
    io_error_uncategorized
)]

use const_str;
use ctor;
use intrusive_collections::{RBTree, UnsafeRef};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::marker;
use std::mem::ManuallyDrop;
use std::ops;
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
mod allocator;
use allocator::new_allocator;
pub use allocator::{Allocator, ALLOCATION_QUANTUM};
use allocator::{ByAddressAdapter, BySizeAddressAdapter, FreeBlock};
mod fd_and_mem;
use fd_and_mem::{commit, rollback, extend_file, save_old_page, os};
use os::MapHolder;

////////////////////////////////////////////////////////////////////////////////
// RAII fixture to handle raw files
#[derive(Debug)]
struct FileHolder(os::File);
impl FileHolder {
    fn new(prefix: &str, extension: &str) -> std::io::Result<Self> {
        let fname = std::format!("{}.{}\0", prefix, extension);
        let r = os::open(&fname)?;
        Ok(Self(r))
    }
    fn read_header_of_header(&self) -> Option<HeaderOfHeader> {
        let mut h = std::mem::MaybeUninit::<HeaderOfHeader>::uninit();
        const S: usize = std::mem::size_of::<HeaderOfHeader>();
        let read =
            unsafe { os::read(self.0, h.as_mut_ptr() as *mut os::Void, S) };
        if read == S {
            Some(unsafe { h.assume_init() })
        } else {
            None
        }
    }
}
impl ops::Deref for FileHolder {
    type Target = os::File;
    fn deref(&self) -> &os::File {
        &self.0
    }
}
impl Drop for FileHolder {
    fn drop(&mut self) {
        os::close(self.0);
    }
}

////////////////////////////////////////////////////////////////////////////////
/// Internal structure to hold all the file and mapping stuff.
///
/// Created by Holder instance and shared by all it's clones in all threads.
#[derive(Debug)]
struct Arena {
    mem: MapHolder,
    fd: FileHolder,      // Main file, mapped onto mem.
    log_fd: FileHolder,  // Log file, consists of pairs (u32 page #, page).
    readers: Mutex<u32>, // Number of readers to apply and revoke flock once.
    page_size: usize,
}

// MapHolder is not Sync and Send because it unsafely leaks arena and size.
// Arena seems to be Sync and Send because it hides mem MapHolder.
unsafe impl Sync for MapHolder {}
unsafe impl Send for MapHolder {}

////////////////////////////////////////////////////////////////////////////////
// Auxilliary constants
/// Ki, kibi.
pub const KI: usize = 1024;
/// Mi, mebi.
pub const MI: usize = 1024 * KI;
/// Gi, gibi.
pub const GI: usize = 1024 * MI;
#[cfg(target_pointer_width = "64")]
/// Ti, tebi.
pub const TI: usize = 1024 * GI;

////////////////////////////////////////////////////////////////////////////////
/// RAII fixture to provide [`Holder::read`] and [`Holder::write`] storage
/// access methods on open files and memory mapping.
///
/// Shares file mapped memory allocation arena with all it's clones.
///
/// Do not mess up with the `Root` type: this crate cannot figure out if the
/// type of root object has been changed someway.
#[derive(Debug, Clone)]
pub struct Holder<Root: Sync + Send> {
    arena: Arc<RwLock<Arena>>,
    phantom: marker::PhantomData<Root>,
}

/// All possible errors of [`Holder`] and arena initialization.
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
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}

/// A [`Holder::open`] result.
pub type Result<T> = std::result::Result<T, Error>;

impl<Root: Sync + Send> Holder<Root> {
    /// Initialize new or open existing persistent allocation space (arena) and
    /// get it's [`Holder`].
    ///
    /// # Arguments
    /// `file_pfx` - main (`.odb`) and log (`.log`) files path prefix.
    ///
    /// `arena_address` - optional address of arena space beginning. Useful for
    ///     avoiding memory clashes after program respawns.
    ///
    /// `arena_size` - size of arena address space. Can grow, but cannot shrink.
    ///
    /// `magick` - user-defined magick number to distinguish among different
    ///     versions of stored structures (i.e. schemas). Dangerous to mess.
    ///
    /// # Safety
    /// - Do not use the same magick on different data schemas. Consider to
    ///   auto-generate magick number depending on software version or data
    ///   schema declaration.
    /// - Consider to depend file name on magick number or software version.
    /// - Do not use pointers to the memory space of a destructed `Holder`.
    /// - In particular, do not leak out (cloned) allocator.
    pub unsafe fn open(
        file_pfx: &str,
        arena_address: Option<usize>,
        arena_size: usize,
        magick: u64,
        new_root: fn(Allocator) -> Root,
    ) -> Result<Self> {
        let ps = os::page_size();
        assert!(ps > 0);
        let page_size = ps as usize;
        assert!(page_size.is_power_of_two());
        let fd = FileHolder::new(file_pfx, "odb")?;
        os::flock_w(*fd);
        let h = fd.read_header_of_header();
        let ld = FileHolder::new(file_pfx, "log")?;
        let aa = match arena_address {
            None => match h {
                None => 0,
                Some(ha) => ha.address,
            },
            Some(a) => match h {
                None => a,
                Some(ha) => {
                    if a == ha.address {
                        a
                    } else {
                        return Err(Error::WrongAddress);
                    }
                }
            },
        } as *mut os::Void;
        let addr = MapHolder::new(*fd, aa, arena_size)?;
        let shown = addr.arena as usize;
        let arena = Arena {
            mem: addr,
            fd,
            log_fd: ld,
            readers: Mutex::new(0),
            page_size,
        };
        let arena = Arc::new(RwLock::new(arena));
        let s = Self { arena, phantom: marker::PhantomData };
        prep_header(&s, magick, shown, arena_size, new_root)?;
        Ok(s)
    }
    /// Shared-lock the storage and get [`Reader`] smart pointer to the `Root`
    /// instance inside the storage.
    pub fn read(&self) -> Reader<Root> {
        let guard = self.arena.read().unwrap();
        {
            let mut readers = guard.readers.lock().unwrap();
            if *readers == 0 {
                os::flock_r(*guard.fd);
                if os::not_empty(*guard.log_fd) {
                    os::unflock(*guard.fd);
                    os::flock_w(*guard.fd);
                    unsafe {
                        rollback::<false>(
                            *guard.fd,
                            *guard.log_fd,
                            guard.mem.arena,
                            guard.page_size,
                        )
                    };
                    os::flock_r(*guard.fd);
                }
            }
            *readers += 1;
        }
        Reader::<Root> {
            guard,
            arena: Arc::clone(&self.arena),
            phantom: marker::PhantomData,
        }
    }
    fn internal_write<const PAGES_WRITABLE_FILE_NOT_LOCKED: bool>(
        &self,
    ) -> InternalWriter<Root, PAGES_WRITABLE_FILE_NOT_LOCKED> {
        let guard = self.arena.write().unwrap();
        if PAGES_WRITABLE_FILE_NOT_LOCKED {
            os::flock_w(*guard.fd);
        }
        unsafe {
            rollback::<false>(
                *guard.fd,
                *guard.log_fd,
                guard.mem.arena,
                guard.page_size,
            )
        };
        let rv = InternalWriter::<Root, PAGES_WRITABLE_FILE_NOT_LOCKED> {
            guard,
            phantom: marker::PhantomData,
        };
        rv.setseg();
        rv
    }
    /// Exclusive-lock the storage and get [`Writer`] smart pointer to the
    /// `Root` instance inside the storage.
    pub fn write(&mut self) -> Writer<Root> {
        self.internal_write::<true>()
    }

    /// Returns the numeric address of the arena space beginning.
    pub fn address(&self) -> usize {
        self.arena.read().unwrap().mem.arena as usize
    }

    /// Returns the size of the arena address space.
    pub fn size(&self) -> usize {
        self.arena.read().unwrap().mem.size as usize
    }
}

////////////////////////////////////////////////////////////////////////////////
// SIGSEGV on write to read-only page and it's handler memory map
impl<Root, const PAGES_WRITABLE: bool>
    InternalWriter<'_, Root, PAGES_WRITABLE>
{
    fn setseg(&self) {
        let g = &self.guard;
        let s = g.mem.size;
        let b = g.mem.arena as *const os::Void;
        let e = unsafe { b.byte_add(s) };
        MEM_MAP.with_borrow_mut(|mb| {
            let c = mb.upper_bound(ops::Bound::Included(&b));
            if let Some((l, ta)) = c.peek_prev() {
                assert!(unsafe { l.byte_add(ta.size) } <= b);
                if let Some((l, _)) = c.peek_next() {
                    assert!(*l >= e);
                }
            }
            mb.insert(b, ThreadArena {
                size: s,
                odb_fd: *g.fd,
                log_fd: *g.log_fd,
                page_size: g.page_size,
            });
        });
    }

    fn remseg(&self) {
        let g = &self.guard;
        let b = g.mem.arena as *const os::Void;
        MEM_MAP.with_borrow_mut(|mb| {
            let r = mb.remove(&b).unwrap();
            assert_eq!(r, ThreadArena {
                size: g.mem.size,
                odb_fd: *g.fd,
                log_fd: *g.log_fd,
                page_size: g.page_size
            });
        });
    }
}

// Returns true if the violation was successfully handled.
unsafe fn memory_violation_handler(
    addr: *const os::Void,
    extend: bool,
) -> bool {
    MEM_MAP.with_borrow(|mb| {
        let c = mb.upper_bound(ops::Bound::Included(&addr));
        if let Some((l, ta)) = c.peek_prev() {
            assert!(l <= &addr);
            if addr < l.byte_add(ta.size) {
                if extend {
                    extend_file(*l, ta.size, ta.odb_fd, ta.page_size, addr);
                } else {
                    save_old_page(*l, ta.size, ta.log_fd, ta.page_size, addr);
                }
                true
            } else {
                false
            }
        } else {
            false
        }
    })
}

#[derive(PartialEq, Debug)]
struct ThreadArena {
    size: usize,
    odb_fd: os::File,
    log_fd: os::File,
    page_size: usize,
}
thread_local! {
    static MEM_MAP: RefCell<BTreeMap<*const os::Void, ThreadArena>> =
        const { RefCell::new(BTreeMap::new()) };
}

#[ctor::ctor]
unsafe fn initialise_sigs() {
    os::initialize_memory_violation_handler(memory_violation_handler);
}

#[ctor::dtor]
unsafe fn finalise_sigs() {
    os::finalize_memory_violation_handler();
}

////////////////////////////////////////////////////////////////////////////////
// Header stored in file
#[repr(C, align(8))]
struct HeaderOfHeader {
    filetype: [u8; 8],   // Letters to show the file type "TMFALLOC"
    version: [u8; 8],    // Crate major version
    endian_bitness: u64, // Number of bits and on what end they start
    magick: u64,         // Error prone fixture to check the user types version
    address: usize,      // Base address of mapping to check
    size: usize,         // Size of mapping to check
    // Ordered intrusive collections of FreeBlock-s.
    by_address: ManuallyDrop<RBTree<ByAddressAdapter>>,
    by_size_address: ManuallyDrop<RBTree<BySizeAddressAdapter>>,
}
#[repr(C, align(8))]
struct Header<Root> {
    h: HeaderOfHeader,
    root: ManuallyDrop<Root>,
}

// Check if the memory map header is ok.
// If empty, then prepare and commit, otherwise rollback.
fn prep_header<Root: Sync + Send>(
    holder: &Holder<Root>,
    magick: u64,
    addr: usize,
    size: usize,
    new_root: fn(Allocator) -> Root,
) -> Result<()> {
    let w = &holder.internal_write::<false>();
    let header_state = header_is_ok_state(magick, addr, size)?;
    match header_state {
        HeaderState::Fine => {}
        HeaderState::NeedsToGrow => grow_up_free_block::<Root>(addr, size, &w),
        HeaderState::Empty => {
            initialize_header::<Root>(addr, size, magick, &w, new_root)
        }
    }
    Ok(())
}
fn grow_up_free_block<Root>(
    addr: usize,
    size: usize,
    w: &InternalWriter<Root, false>,
) {
    let hp = addr as *mut Header<Root>;
    let ptr = unsafe { hp.as_mut() }.unwrap();
    let p = unsafe { hp.byte_add(ptr.h.size) } as *const FreeBlock;
    let ph = &mut ptr.h;
    let cl = ph.by_address.back_mut();
    let old_size = ph.size;
    match cl.get() {
        // lower neighbour
        None => unsafe {
            FreeBlock::initialize(
                ph,
                hp.byte_add(old_size) as *const FreeBlock,
                size - old_size,
            )
        },
        Some(l) => unsafe {
            let lp = l as *const FreeBlock;
            if lp.byte_add(l.size) < p {
                FreeBlock::initialize(
                    ph,
                    hp.byte_add(old_size) as *const FreeBlock,
                    size - old_size,
                )
            } else {
                ph.by_size_address.cursor_mut_from_ptr(lp).remove();
                let lr = lp.cast_mut().as_mut().unwrap();
                lr.size += size - old_size;
                ph.by_size_address.insert(UnsafeRef::from_raw(lp));
            }
        },
    };
    ph.size = size;
    let wg = &w.guard;
    unsafe { commit(*wg.fd, *wg.log_fd, wg.mem.arena, wg.mem.size) };
}
fn initialize_header<Root>(
    addr: usize,
    size: usize,
    magick: u64,
    w: &InternalWriter<Root, false>,
    new_root: fn(Allocator) -> Root,
) {
    let hp = addr as *mut Header<Root>;
    let ptr = unsafe { hp.as_mut() }.unwrap();
    let h = HeaderOfHeader {
        filetype: FILETYPE,
        version: VERSION,
        endian_bitness: ENDIAN_BITNESS,
        magick,
        address: addr,
        size,
        by_address: ManuallyDrop::new(RBTree::new(ByAddressAdapter::new())),
        by_size_address: ManuallyDrop::new(RBTree::new(
            BySizeAddressAdapter::new(),
        )),
    };
    ptr.h = h;
    let fbraw = unsafe { hp.add(1) };
    let fbaddr = fbraw as usize;
    let fbraw = unsafe {
        fbraw.byte_add(ALLOCATION_QUANTUM - (fbaddr % ALLOCATION_QUANTUM))
    } as *mut FreeBlock;
    unsafe {
        FreeBlock::initialize(
            &mut ptr.h,
            fbraw,
            hp.byte_add(size).byte_offset_from(fbraw).try_into().unwrap(),
        )
    };
    ptr.root = ManuallyDrop::new(new_root(w.allocator()));
    let wg = &w.guard;
    unsafe { commit(*wg.fd, *wg.log_fd, wg.mem.arena, wg.mem.size) };
}
const FILETYPE: [u8; 8] = const_str::to_byte_array!(b"TMFALLOC");
const V: &str = env!("CARGO_PKG_VERSION_MAJOR");
const V_PREF: &str = const_str::repeat!(" ", 8 - V.len());
const V_STR: &str = const_str::concat!(V_PREF, V);
const VERSION: [u8; 8] = const_str::to_byte_array!(V_STR);
const ENDIAN_BITNESS: u64 = std::mem::size_of::<usize>() as u64;
enum HeaderState {
    Empty,
    NeedsToGrow,
    Fine,
}
fn header_is_ok_state(
    magick: u64,
    address: usize,
    size: usize,
) -> Result<HeaderState> {
    let ptr = unsafe { (address as *const HeaderOfHeader).as_ref() }.unwrap();
    if ptr.filetype == [0; 8] && ptr.magick == 0 && ptr.address == 0 {
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
    } else {
        Ok(HeaderState::Fine)
    }
}

////////////////////////////////////////////////////////////////////////////////
/// A smart pointer to the `Root` for storage concurrent read access.
///
/// Can be created by [`Holder::read`] method. Holds shared locks to the memory
/// mapped file storage until dropped. Provides shared read access to the `Root`
/// persistent instance.
pub struct Reader<'a, Root> {
    guard: RwLockReadGuard<'a, Arena>,
    arena: Arc<RwLock<Arena>>,
    phantom: marker::PhantomData<&'a Root>,
}
impl<Root> ops::Deref for Reader<'_, Root> {
    type Target = Root;
    fn deref(&self) -> &Root {
        &unsafe { (self.guard.mem.arena as *const Header<Root>).as_ref() }
            .unwrap()
            .root
    }
}
impl<Root> Drop for Reader<'_, Root> {
    fn drop(&mut self) {
        let arena = self.arena.read().unwrap();
        let mut readers = arena.readers.lock().unwrap();
        if *readers == 1 {
            os::unflock(*arena.fd);
        }
        assert!(*readers > 0);
        *readers -= 1;
    }
}

////////////////////////////////////////////////////////////////////////////////
// InternalWriter accessor to allow storage exclusive write access.
/// A smart pointer to the `Root` for storage exclusive write access.
///
/// Not indended for direct creation by a user. See [`Writer`].
pub struct InternalWriter<'a, Root, const PAGES_WRITABLE: bool> {
    guard: RwLockWriteGuard<'a, Arena>,
    //_arena: Arc<RwLock<Arena>>,
    phantom: marker::PhantomData<&'a Root>,
}
impl<'a, Root, const PAGES_WRITABLE: bool>
    InternalWriter<'a, Root, PAGES_WRITABLE>
{
    /// Rollback the current transaction. Automatically called in
    /// [`InternalWriter::drop`] method.
    pub fn rollback(&self) {
        let g = &self.guard;
        unsafe {
            rollback::<PAGES_WRITABLE>(
                *g.fd,
                *g.log_fd,
                g.mem.arena,
                g.page_size,
            )
        };
    }
    /// Commit the current transaction. Call to save the data.
    pub fn commit(&self) {
        let g = &self.guard;
        unsafe { commit(*g.fd, *g.log_fd, g.mem.arena, g.mem.size) };
    }
    /// Create allocator to use in collections and containers.
    pub fn allocator(&self) -> Allocator {
        new_allocator(self.guard.mem.arena as usize)
    }
}
impl<Root, const PAGES_WRITABLE: bool> ops::Deref
    for InternalWriter<'_, Root, PAGES_WRITABLE>
{
    type Target = Root;
    fn deref(&self) -> &Root {
        &unsafe { (self.guard.mem.arena as *const Header<Root>).as_ref() }
            .unwrap()
            .root
    }
}
impl<Root, const PAGES_WRITABLE: bool> ops::DerefMut
    for InternalWriter<'_, Root, PAGES_WRITABLE>
{
    fn deref_mut(&mut self) -> &mut Root {
        &mut unsafe { (self.guard.mem.arena as *mut Header<Root>).as_mut() }
            .unwrap()
            .root
    }
}
impl<Root, const PAGES_WRITABLE: bool> Drop
    for InternalWriter<'_, Root, PAGES_WRITABLE>
{
    fn drop(&mut self) {
        let a = &self.guard;
        unsafe {
            rollback::<PAGES_WRITABLE>(
                *a.fd,
                *a.log_fd,
                a.mem.arena,
                a.page_size,
            )
        };
        self.remseg();
        os::unflock(*a.fd);
    }
}

/// A smart pointer to the `Root` for storage exclusive write access.
///
/// Can be created by [`Holder::write`] method. Holds exclusive locks to the
/// memory mapped file storage until dropped. Provides exclusive write access to
/// the `Root` persistent instance.
pub type Writer<'a, Root> = InternalWriter<'a, Root, true>;

#[cfg(test)]
mod tests;
