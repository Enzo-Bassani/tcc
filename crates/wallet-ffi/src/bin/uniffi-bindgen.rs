//! The UniFFI bindings generator for this crate. Built with `--features cli`:
//! `cargo run -p wallet-ffi --features cli --bin uniffi-bindgen -- generate \
//!     --library <path/to/libwallet_ffi.so> --language kotlin --out-dir <dir>`.
fn main() {
    uniffi::uniffi_bindgen_main()
}
