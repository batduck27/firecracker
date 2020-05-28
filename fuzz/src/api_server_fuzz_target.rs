use api_server::fuzzing::*;

#[cfg(feature = "afl_fuzz")]
#[macro_use]
extern crate afl;
#[cfg(feature = "afl_fuzz")]
fn main() {
    fuzz!(|data: &[u8]| {
        api_server_fuzzing(data);
    });
}

#[cfg(feature = "stdin_fuzz")]
fn main() {
    use std::io::Read;

    let mut data = Vec::with_capacity(8192);
    std::io::stdin().read_to_end(&mut data).unwrap();
    api_server_fuzzing(&data);
}
