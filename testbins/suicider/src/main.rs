#![feature(allocator_api)]
use std::io;
use std::io::Write;
use std::process;
use tmfalloc::{Holder, MI, KI, Allocator};

fn main() {
    let mut h = Holder::<Vec<i64, Allocator>>::new(
        "test_read_recovery",
        None,
        MI,
        0xfedcba9876543210,
        |_| panic!("Impossible!"),
    )
    .unwrap();
    let mut w = h.write();
    w.truncate(0);
    let v: Vec<i64> = (0i64..120 * KI as i64).rev().collect();
    w.extend_from_slice(&v);
    println!("w: {}", w[w.len() - 1] - w[0]);
    io::stdout().flush().unwrap();
    process::abort();
}
