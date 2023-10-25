use std::process;
use tmfalloc::{MI, Holder};
use std::io;
use std::io::Write;

fn main() {
    let mut h = Holder::<u64>::new(
        "test_read_recovery",
        None,
        MI,
        0xfedcba9876543210,
        |_| panic!("Impossible!"),
    )
    .unwrap();
    let mut w = h.write();
    *w = 1;
    println!("w: {}", *w);
    io::stdout().flush().unwrap();
    process::abort();
}

