fn main() {
    if cfg!(target_os = "linux") {
        if cfg!(feature = "boehm") {
            println!(r"cargo:rustc-link-lib=monoboehm-2.0");
        } else if cfg!(feature = "sgen") {
            println!(r"cargo:rustc-link-lib=monosgen-2.0");
        } else {
            println!(r"cargo:rustc-link-lib=mono-2.0");
        }
    } else {
        if cfg!(feature = "boehm") {
            println!(r"cargo:rustc-link-lib=mono-2.0-bdwgc");
            println!(r"cargo:rustc-link-search=lib");
        } else if cfg!(feature = "sgen") {
            println!(r"cargo:rustc-link-lib=mono-2.0-sgen");
            println!(r"cargo:rustc-link-search=C:\Program Files\Mono\lib");
        } else {
            panic!("No mono variant selected. Requires feature boehm (for bdwgc) or sgen");
        }
    }
}
