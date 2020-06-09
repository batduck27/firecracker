#![cfg_attr(feature = "libfuzzer_fuzz", no_main)]

use devices::virtio::vsock::device::fuzzing::*;

#[cfg(feature = "afl_fuzz")]
#[macro_use]
extern crate afl;

#[cfg(feature = "honggfuzz_fuzz")]
#[macro_use]
extern crate honggfuzz;

#[cfg(feature = "libfuzzer_fuzz")]
#[macro_use]
extern crate libfuzzer_sys;

#[cfg(feature = "afl_fuzz")]
fn main() {
    fuzz!(|data: &[u8]| {
        vsock_fuzzing(data);
    });
}

#[cfg(feature = "honggfuzz_fuzz")]
fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            vsock_fuzzing(data);
        });
    }
}

#[cfg(feature = "libfuzzer_fuzz")]
fuzz_target!(|data: &[u8]| {
    vsock_fuzzing(data);
});


#[cfg(feature = "stdin_fuzz")]
fn main() {
    use std::io::Read;

    let mut data = Vec::with_capacity(8192);
    std::io::stdin().read_to_end(&mut data).unwrap();
    vsock_fuzzing(&data);
}
