

pub unsafe extern "sysv64" fn push_integer<I: itoa::Integer>(value: I, dst: *mut u8) -> usize {
    let mut buffer = itoa::Buffer::new();
    let printed = buffer.format(value);
    std::ptr::copy_nonoverlapping(printed.as_ptr(), dst, printed.len());
    printed.len()
}

pub unsafe extern "sysv64" fn calc_integer_size<I: itoa::Integer>(value: I) -> usize {
    let mut buffer = itoa::Buffer::new();
    let printed = buffer.format(value);
    printed.len()
}

#[macro_export]
macro_rules! emit_integer {
    ($ty:ty, $offset:expr, $mov:ident, $reg:ident, $width:expr, $assembler:ident) => {
        if $offset == 0 {
            json_dynasm!($assembler
                ; $mov $reg, $width [object]
            );
        } else {
            json_dynasm!($assembler
                ; $mov $reg, $width [object + $offset]
            );
        }
        json_dynasm!($assembler
            ; mov rsi, buffer
            ; mov temp, QWORD integer::push_integer::<$ty> as _
            ; call temp
            ; add buffer, retval
        )
    };
}

#[macro_export]
macro_rules! emit_integer_size {
    ($ty:ty, $offset:expr, $mov:ident, $reg:ident, $width:expr, $assembler:ident) => {
        if $offset == 0 {
            json_dynasm!($assembler
                ; $mov $reg, $width [object]
            );
        } else {
            json_dynasm!($assembler
                ; $mov $reg, $width [object + $offset]
            );
        }
        json_dynasm!($assembler
            ; mov temp, QWORD integer::calc_integer_size::<$ty> as _
            ; call temp
            ; add buffer, retval
        )
    };
}
