// Memory mapped transaction protected file storage allocator for Rust


// Pass this to all containers to be stored as the generic argument A.
pub struct Allocator<const ARENA_ID: u8>;

impl<const ARENA_ID: u8> Allocator<ARENA_ID> {
}

pub struct Accessor<const ARENA_ID: u8, Root> {
}

impl<const ARENA_ID: u8, Root> Accessor<ARENA_ID, Root> {
    pub fn new() -> Result<Accessor<ARENA_ID, Root>, Err>
                        (file: &str, arena_address: usize, arena_size: usize) {
        MmtsAllocator { fd, arena, arena_size, 0 }
    }

    }
    fn mutableRoot(&self) -> Result<MutableRootBox<Root>, > {
        panic_syserr!(libc::flock(self.fd, libc::LOCK_EX),
            "Could not flock the storage file in exclusive mode");
        MutableRootBox<Root> {
            self
        }
    }
    fn immutableRoot(&self) -> ImmutableRootBox<Root> {
        panic_syserr!(libc::flock(self.fd, libc::LOCK_SH),
            "Could not flock the storage file in shared mode");
        ImmutableRootBox<Root> {
            self
        }
    }
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
