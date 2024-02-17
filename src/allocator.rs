use super::HeaderOfHeader;
use super::MEM_MAP;
use super::os::Void;
use std::ops;
use intrusive_collections::intrusive_adapter;
use intrusive_collections::Bound::Included as IntrusiveIncluded;
use intrusive_collections::{KeyAdapter, RBTreeLink, UnsafeRef};
use std::alloc::{AllocError, Allocator as StdAllocator, Layout};
use std::mem::ManuallyDrop;
use std::ptr::{copy_nonoverlapping, NonNull};

////////////////////////////////////////////////////////////////////////////////
// Red-black trees allocator muscellaneous stuff

// FreeBlock: a (header of) piece of empty space.
pub struct FreeBlock {
    by_size_address: RBTreeLink,
    by_address: RBTreeLink,
    pub size: usize,
    _padding: usize,
}
/// Common divisor of any allocation arena consumption in bytes.
pub const ALLOCATION_QUANTUM: usize = std::mem::size_of::<FreeBlock>();
impl FreeBlock {
    pub(crate) unsafe fn initialize(
        h: &mut HeaderOfHeader,
        fbr: *const FreeBlock,
        size: usize,
    ) {
        let fbptr = fbr as *mut ManuallyDrop<FreeBlock>;
        let fbref = fbptr.as_mut().unwrap();
        fbref._padding = !fbref._padding; // Cause SIGBUS if file too small.
        *fbref = ManuallyDrop::new(FreeBlock {
            by_address: RBTreeLink::new(),
            by_size_address: RBTreeLink::new(),
            size,
            _padding: 0,
        });
        h.by_address.insert(UnsafeRef::from_raw(fbr));
        h.by_size_address.insert(UnsafeRef::from_raw(fbr));
    }
    pub(crate) unsafe fn finalize(
        h: &mut HeaderOfHeader,
        fbr: *const FreeBlock,
    ) {
        h.by_address.cursor_mut_from_ptr(fbr).remove();
        h.by_size_address.cursor_mut_from_ptr(fbr).remove();
    }
}
intrusive_adapter!(pub ByAddressAdapter = UnsafeRef<FreeBlock>:
                            FreeBlock { by_address: RBTreeLink });
impl<'a> KeyAdapter<'a> for ByAddressAdapter {
    type Key = *const FreeBlock;
    fn get_key(&self, x: &'a FreeBlock) -> Self::Key {
        x as *const FreeBlock
    }
}
intrusive_adapter!(pub BySizeAddressAdapter = UnsafeRef<FreeBlock>:
                            FreeBlock { by_size_address: RBTreeLink });
impl<'a> KeyAdapter<'a> for BySizeAddressAdapter {
    type Key = (usize, *const FreeBlock);
    fn get_key(&self, x: &'a FreeBlock) -> Self::Key {
        (x.size, x as *const FreeBlock)
    }
}

////////////////////////////////////////////////////////////////////////////////
/// Allocator applicable for standard containers to make them persistent.
///
/// Create [`crate::Writer`] by [`crate::Holder::write`] in the same thread for
/// allocation, deallocation and other persistent storage update.
#[derive(Clone)]
pub struct Allocator {
    address: usize,
}

pub fn new_allocator(address: usize) -> Allocator {
    Allocator { address }
}

fn check_mem_map_exists(address: usize) {
    let a = address as *const Void;
    assert!(MEM_MAP.with_borrow(|mb| {
        let c = mb.upper_bound(ops::Bound::Included(&a));
        if let Some((l, _)) = c.peek_prev() {
            *l == a
        } else { false }
    }), "tmfalloc::Allocator has been used in non-writing thread");
}

unsafe impl StdAllocator for Allocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let s = layout.size() + layout.padding_needed_for(ALLOCATION_QUANTUM);
        check_mem_map_exists(self.address);
        let h = unsafe { (self.address as *mut HeaderOfHeader).as_mut() };
        allocate(s, h.unwrap())
    }
    unsafe fn deallocate(&self, p: NonNull<u8>, layout: Layout) {
        let s = layout.size() + layout.padding_needed_for(ALLOCATION_QUANTUM);
        check_mem_map_exists(self.address);
        assert!(s % ALLOCATION_QUANTUM == 0);
        let h = unsafe { (self.address as *mut HeaderOfHeader).as_mut() };
        let p = p.as_ptr() as *const FreeBlock;
        deallocate(s, p, h.unwrap())
    }
    unsafe fn grow(
        &self,
        p: NonNull<u8>,
        old: Layout,
        new: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        check_mem_map_exists(self.address);
        let os = old.size() + old.padding_needed_for(ALLOCATION_QUANTUM);
        let ns = new.size() + new.padding_needed_for(ALLOCATION_QUANTUM);
        if os == ns {
            return Ok(NonNull::slice_from_raw_parts(p, ns));
        }
        let h = (self.address as *mut HeaderOfHeader).as_mut().unwrap();
        let fbp = p.as_ptr() as *const FreeBlock;
        let cu = h.by_address.lower_bound(IntrusiveIncluded(&fbp));
        if let Some(u) = cu.get() {
            // upper neighbour
            let ufb = u as *const FreeBlock;
            let us = os + (*ufb).size; // Useable size
            if fbp.byte_add(os) == ufb && us >= ns {
                FreeBlock::finalize(h, ufb);
                if us > ns {
                    // XXX How to use finalized pointers in initialize?
                    FreeBlock::initialize(h, ufb.byte_add(ns - os), us - ns);
                }
                return Ok(NonNull::slice_from_raw_parts(p, ns));
            }
        }
        let r = allocate(ns, h)?;
        copy_nonoverlapping(p.as_ptr(), r.as_mut_ptr(), new.size());
        deallocate(os, fbp, h); // XXX Reuse cu in the deallocator?
        Ok(r)
    }
    unsafe fn shrink(
        &self,
        p: NonNull<u8>,
        old: Layout,
        new: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        check_mem_map_exists(self.address);
        let os = old.size() + old.padding_needed_for(ALLOCATION_QUANTUM);
        let ns = new.size() + new.padding_needed_for(ALLOCATION_QUANTUM);
        let h = (self.address as *mut HeaderOfHeader).as_mut().unwrap();
        let fbp = p.as_ptr() as *const FreeBlock;
        assert!(ns >= ALLOCATION_QUANTUM);
        let cu = h.by_address.lower_bound(IntrusiveIncluded(&fbp));
        let new_block_size = if let Some(u) = cu.get() {
            // upper neighbour
            let ufb = u as *const FreeBlock;
            if fbp.byte_add(os) == ufb {
                FreeBlock::finalize(h, ufb);
                os - ns + (*ufb).size
            } else {
                os - ns
            }
        } else {
            os - ns
        };
        assert!(new_block_size >= ALLOCATION_QUANTUM);
        // XXX Reuse cu and finalized poiners in initialize?
        FreeBlock::initialize(h, fbp.byte_add(ns), new_block_size);
        Ok(NonNull::slice_from_raw_parts(p, ns))
    }
}

// The address and size-address orders (de)allocation.
fn allocate(
    s: usize,
    h: &mut HeaderOfHeader,
) -> std::result::Result<NonNull<[u8]>, AllocError> {
    let c = h
        .by_size_address
        .lower_bound(IntrusiveIncluded(&(s, std::ptr::null::<FreeBlock>())));
    match c.get() {
        None => Err(AllocError),
        Some(r) => {
            let p = r as *const FreeBlock;
            let rs = r.size;
            unsafe { FreeBlock::finalize(h, p) };
            if rs > s {
                let n = unsafe { p.byte_add(s) } as *mut FreeBlock;
                unsafe { FreeBlock::initialize(h, n, rs - s) };
            }
            Ok(NonNull::slice_from_raw_parts(
                NonNull::new(p as *mut u8).unwrap(),
                s,
            ))
        }
    }
}

unsafe fn deallocate(s: usize, p: *const FreeBlock, h: &mut HeaderOfHeader) {
    // XXX These cursors point to neighbours, so could be optimized?
    let cu = h.by_address.lower_bound(IntrusiveIncluded(&p));
    let cl = h.by_address.upper_bound(IntrusiveIncluded(&p));
    let ln = match cl.get() {
        // lower neighbour
        None => None,
        Some(l) => {
            if (l as *const FreeBlock).byte_add(l.size) < p {
                None
            } else {
                Some(l as *const FreeBlock)
            }
        }
    };
    let un = match cu.get() {
        // upper neighbour
        None => None,
        Some(u) => {
            if p.byte_add(s) < u as *const FreeBlock {
                None
            } else {
                Some((u as *const FreeBlock, u.size))
            }
        }
    };
    match ln {
        None => match un {
            None => FreeBlock::initialize(h, p, s),
            Some((up, us)) => {
                FreeBlock::finalize(h, up as *const FreeBlock);
                FreeBlock::initialize(h, p, s + us);
            }
        },
        Some(lp) => {
            let lr = lp.cast_mut().as_mut().unwrap();
            h.by_size_address.cursor_mut_from_ptr(lp).remove();
            match un {
                None => lr.size += s,
                Some((up, us)) => {
                    FreeBlock::finalize(h, up);
                    lr.size += s + us;
                }
            };
            h.by_size_address.insert(unsafe { UnsafeRef::from_raw(lp) });
        }
    }
}
