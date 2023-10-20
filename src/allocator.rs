use std::alloc::{Layout, AllocError, Allocator as StdAllocator};
use std::ptr::{NonNull, copy_nonoverlapping};
use intrusive_collections::Bound::Included as IntrusiveIncluded;
use intrusive_collections::UnsafeRef;
use super::{FreeBlock, HeaderOfHeader, ALLOCATION_QUANTUM};
////////////////////////////////////////////////////////////////////////////////
/// Allocator applicable for standard containers to make them persistent
///
/// Create [super::Writer] by [super::Holder::write] in the same thread before 
/// allocation, deallocation and other persistent storage update.
#[derive(Clone)]
pub struct Allocator {
    pub address: usize,
}

unsafe impl StdAllocator for Allocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let s = layout.size() + layout.padding_needed_for(ALLOCATION_QUANTUM);
        let h = unsafe { (self.address as *mut HeaderOfHeader).as_mut() };
        allocate(s, h.unwrap())
    }
    unsafe fn deallocate(&self, p: NonNull<u8>, layout: Layout) {
        let s = layout.size() + layout.padding_needed_for(ALLOCATION_QUANTUM);
        assert!(s % ALLOCATION_QUANTUM == 0);
        let h = unsafe { (self.address as *mut HeaderOfHeader).as_mut() };
        let p = p.as_ptr() as *const FreeBlock;
        deallocate(s, p, h.unwrap())
    }
    unsafe fn grow(&self, p: NonNull<u8>, old: Layout, new: Layout) ->
            Result<NonNull<[u8]>, AllocError> {
        let os = old.size() + old.padding_needed_for(ALLOCATION_QUANTUM);
        let ns = new.size() + new.padding_needed_for(ALLOCATION_QUANTUM);
        if os == ns {
            return Ok(NonNull::slice_from_raw_parts(p, ns))
        }
        let h = (self.address as *mut HeaderOfHeader).as_mut().unwrap();
        let fbp = p.as_ptr() as *const FreeBlock;
        let cu = h.by_address.lower_bound(IntrusiveIncluded(&fbp));
        if let Some(u) = cu.get() { // upper neighbour
            let ufb = u as *const FreeBlock;
            let us = os + (*ufb).size; // Useable size
            if fbp.byte_add(os) == ufb && us >= ns {
                FreeBlock::finalize(h, ufb);
                if us > ns { // XXX How to use finalized pointers in initialize?
                    FreeBlock::initialize(h, ufb.byte_add(ns - os), us - ns);
                }
                return Ok(NonNull::slice_from_raw_parts(p, ns))
            }
        }
        let r = allocate(ns, h)?;
        copy_nonoverlapping(p.as_ptr(), r.as_mut_ptr(), new.size());
        deallocate(os, fbp, h); // XXX Reuse cu in the deallocator?
        Ok(r)
    }
    unsafe fn shrink(&self, p: NonNull<u8>, old: Layout, new: Layout) ->
            Result<NonNull<[u8]>, AllocError> {
        let os = old.size() + old.padding_needed_for(ALLOCATION_QUANTUM);
        let ns = new.size() + new.padding_needed_for(ALLOCATION_QUANTUM);
        let h = (self.address as *mut HeaderOfHeader).as_mut().unwrap();
        let fbp = p.as_ptr() as *const FreeBlock;
        assert!(ns >= ALLOCATION_QUANTUM);
        let cu = h.by_address.lower_bound(IntrusiveIncluded(&fbp));
        let new_block_size = if let Some(u) = cu.get() { // upper neighbour
            let ufb = u as *const FreeBlock;
            if fbp.byte_add(os) == ufb {
                FreeBlock::finalize(h, ufb);
                os - ns + (*ufb).size
            } else { os - ns }
        } else { os - ns };
        assert!(new_block_size >= ALLOCATION_QUANTUM);
        // XXX Reuse cu and finalized poiners in initialize?
        FreeBlock::initialize(h, fbp.byte_add(ns), new_block_size);
        Ok(NonNull::slice_from_raw_parts(p, ns))
    }
}

// The address and size-address orders (de)allocation.
fn allocate(s: usize, h: &mut HeaderOfHeader) ->
        std::result::Result<NonNull<[u8]>, AllocError> {
    let c = h.by_size_address.lower_bound(
                    IntrusiveIncluded(&(s, std::ptr::null::<FreeBlock>())));
    match c.get() {
        None => Err(AllocError),
        Some(r) => {
            let p = r as *const FreeBlock;
            let rs = r.size;
            FreeBlock::finalize(h, p);
            if rs > s {
                let n = unsafe{ p.byte_add(s) } as *mut FreeBlock;
                FreeBlock::initialize(h, n, rs - s);
            }
            Ok(NonNull::slice_from_raw_parts(
                                NonNull::new(p as *mut u8).unwrap(), s))
        }
    }
}

unsafe fn deallocate(s: usize, p: *const FreeBlock, h: &mut HeaderOfHeader) {
    // XXX These cursors point to neighbours, so could be optimized?
    let cu = h.by_address.lower_bound(IntrusiveIncluded(&p));
    let cl = h.by_address.upper_bound(IntrusiveIncluded(&p));
    let ln = match cl.get() { // lower neighbour
        None => None,
        Some(l) => if (l as *const FreeBlock).byte_add(l.size) < p { None }
                    else { Some(l as *const FreeBlock) }
    };
    let un = match cu.get() { // upper neighbour
        None => None,
        Some(u) => if p.byte_add(s) < u as *const FreeBlock { None }
                    else { Some((u as *const FreeBlock, u.size)) }
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
            h.by_size_address.insert(unsafe { UnsafeRef::from_raw(lp) } );
        }
    }
}

