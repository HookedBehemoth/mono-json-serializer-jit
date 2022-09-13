mod mono;

use dynasmrt::*;
use mono::*;

use std::{alloc, arch::asm, ffi::CStr, ptr};

macro_rules! json_dynasm {
    ($ops:ident $($t:tt)*) => {
        dynasm!($ops
            ; .arch x64

            ; .alias object, r15
            ; .alias buffer, r14

            ; .alias temp, rdx
            ; .alias temp_32, edx
            ; .alias temp_16, dx
            ; .alias temp_8, dl

            ; .alias retval, rax
            $($t)*
        )
    }
}

type Assembler = dynasmrt::Assembler<x64::X64Relocation>;

unsafe fn emit_boolean(field_offset: i32, assembler: &mut Assembler) {
    json_dynasm!(assembler
        ; mov temp_8, BYTE [object + field_offset]
        ; test temp_8, temp_8
        ; je >not
        ;;emit_string_copy("true", assembler)
        ; jmp >exit
        ;not:
        ;;emit_string_copy("false", assembler)
        ; exit:
    );
}

#[cfg(feature = "utf")]
mod utf16 {
    use dynasmrt::*;

    pub unsafe extern "sysv64" fn push_string(s: *const crate::MonoString, dst: *mut u8) -> usize {
        simdutf::convert_valid_utf16le_to_utf8(&(*s).chars as *const u16, (*s).length as _, dst)
    }

    pub unsafe extern "sysv64" fn push_char(s: *const u16, dst: *mut u8) -> usize {
        simdutf::convert_valid_utf16le_to_utf8(s, 1, dst)
    }

    pub unsafe extern "sysv64" fn calc_string_size(s: *const crate::MonoString) -> usize {
        let slice = std::slice::from_raw_parts(&(*s).chars as *const u16, (*s).length as _);
        simdutf::count_utf8_from_utf16le(slice)
    }

    pub unsafe extern "sysv64" fn calc_char_size(s: *const u16) -> usize {
        let slice = std::slice::from_raw_parts(s, 1);
        simdutf::count_utf8_from_utf16le(slice)
    }

    pub fn emit_char(field_offset: i32, assembler: &mut crate::Assembler) {
        json_dynasm!(assembler
            ;;crate::emit_string_copy("\"", assembler)

            ; lea rdi, [object + field_offset]
            ; mov rsi, buffer
            ; mov temp, QWORD push_char as _
            ; call temp
            ; add buffer, retval

            ;;crate::emit_string_copy("\"", assembler)
        );
    }

    pub fn emit_string_size(assembler: &mut crate::Assembler) {
        json_dynasm!(assembler
            ; mov temp, QWORD calc_string_size as _
            ; call temp
            ; add buffer, retval
        );
    }

    pub fn emit_char_length(field_offset: i32, assembler: &mut crate::Assembler) {
        json_dynasm!(assembler
            ; lea rdi, [object + field_offset]
            ; mov temp, QWORD calc_char_size as _
            ; call temp
            ; add buffer, retval
        );
    }
}
#[cfg(not(feature = "utf"))]
mod utf16 {
    use dynasmrt::*;

    pub unsafe extern "sysv64" fn push_string(s: *const crate::MonoString, dst: *mut u8) -> usize {
        for i in 0..((*s).length as usize) {
            *dst.add(i) = *(&(*s).chars as *const u16).add(i) as _;
        }
        (*s).length as _
    }

    pub fn emit_char(field_offset: i32, assembler: &mut crate::Assembler) {
        json_dynasm!(assembler
            ;;crate::emit_string_copy("\"", assembler)
            ; mov temp_8, [object + field_offset]
            ; mov BYTE [buffer], temp_8
            ; add buffer, 1
            ;;crate::emit_string_copy("\"", assembler)
        );
    }

    pub fn emit_string_size(assembler: &mut crate::Assembler) {
        json_dynasm!(assembler
            ; mov rdi, [rdi + 0x18]
            ; add buffer, rdi
        );
    }

    pub fn emit_char_length(_: i32, assembler: &mut crate::Assembler) {
        json_dynasm!(assembler
            ; add buffer, 1
        );
    }
}

unsafe extern "sysv64" fn push_float<F: ryu::Float>(value: F, dst: *mut u8) -> usize {
    let mut buffer = ryu::Buffer::new();
    let printed = buffer.format(value);
    ptr::copy_nonoverlapping(printed.as_ptr(), dst, printed.len());
    printed.len()
}

unsafe extern "sysv64" fn calc_float_size<F: ryu::Float>(value: F) -> usize {
    let mut buffer = ryu::Buffer::new();
    let printed = buffer.format(value);
    printed.len()
}

unsafe extern "sysv64" fn push_integer<I: itoa::Integer>(value: I, dst: *mut u8) -> usize {
    let mut buffer = itoa::Buffer::new();
    let printed = buffer.format(value);
    ptr::copy_nonoverlapping(printed.as_ptr(), dst, printed.len());
    printed.len()
}

unsafe extern "sysv64" fn calc_integer_size<I: itoa::Integer>(value: I) -> usize {
    let mut buffer = itoa::Buffer::new();
    let printed = buffer.format(value);
    printed.len()
}

/**
 * Pack strings into 64, 32 and 16 bit moves instead of
 * looping over very string.
 */
fn emit_string_copy(string: &str, assembler: &mut Assembler) {
    macro_rules! pack {
        ($ty:ty, $span:expr, $offset:expr) => {
            <$ty>::from_le_bytes(unsafe {
                $span
                    .get_unchecked($offset..$offset + std::mem::size_of::<$ty>())
                    .try_into()
                    .unwrap_unchecked()
            })
        };
    }

    macro_rules! emit_mov {
        ($offset:expr, $width:ident, $value:expr) => {
            if ($offset == 0) {
                json_dynasm!(assembler
                    ; mov $width [buffer], $value
                );
            } else {
                json_dynasm!(assembler
                    ; mov $width [buffer + $offset as _], $value
                );
            }
        };
    }

    let s: &[u8] = string.as_bytes();
    let mut offset: usize = 0;

    while offset + 8 <= s.len() {
        json_dynasm!(assembler
            ; mov temp, QWORD pack!(u64, s, offset) as i64
        );

        if offset == 0 {
            json_dynasm!(assembler
                ; mov QWORD [buffer], temp
            );
        } else {
            json_dynasm!(assembler
                ; mov QWORD [buffer + offset as i32], temp
            );
        }
        offset += 8;
    }

    if offset + 4 <= s.len() {
        emit_mov!(offset, DWORD, pack!(u32, s, offset) as i32);
        offset += 4;
    }

    if offset + 2 <= s.len() {
        emit_mov!(offset, WORD, pack!(u16, s, offset) as i16);
        offset += 2;
    }

    if offset < s.len() {
        emit_mov!(offset, BYTE, s[offset] as i8);
    }

    json_dynasm!(assembler
        ; add buffer, s.len() as _
    );
}

unsafe fn emit_array(field_offset: i32, eclass: *const MonoClass, assembler: &mut Assembler) {
    let stride = mono_class_array_element_size(eclass);
    let typ = mono_class_get_type(eclass);

    let empty_label = assembler.new_dynamic_label();
    let repeat_label = assembler.new_dynamic_label();
    json_dynasm!(assembler
        ; push object
        ; push r12
        ; push r13

        /* load object */
        ; mov object, [object + field_offset]

        /* check for null */
        ; test object, object
        ; je =>empty_label

        /* skip empty arrays */
        ; mov r13d, DWORD [object + 0x18]
        ; test r13, r13
        ; je =>empty_label

        ;;emit_string_copy("[", assembler)

        /* loop init */
        ; lea object, [object + 0x20]
        ; xor r12, r12
        ; jmp >push

        /* push comma starting with the second item */
        ;=>repeat_label
        ;;emit_string_copy(",", assembler)

        /* serialize value */
        ;push:
        ; push object
        ;;emit_serialize_value(typ, 0, assembler)
        ; pop object

        /* move to next object and increment counter */
        ; add object, stride
        ; add r12, 1
        ; cmp r12, r13
        ; jb =>repeat_label

        ;;emit_string_copy("]", assembler)
        ; jmp >exit

        /* push empty array */
        ;=>empty_label
        ;;emit_string_copy("[]", assembler)

        ;exit:
        ; pop r13
        ; pop r12
        ; pop object
    );
}

unsafe fn emit_array_size(field_offset: i32, eclass: *const MonoClass, assembler: &mut Assembler) {
    let stride = mono_class_array_element_size(eclass);
    let typ = mono_class_get_type(eclass);

    let exit_label = assembler.new_dynamic_label();
    let repeat_label = assembler.new_dynamic_label();
    json_dynasm!(assembler
        ; push object
        ; push r12
        ; push r13

        /* load object */
        ; mov object, [object + field_offset]

        /* check for null */
        ; test object, object
        ; je =>exit_label

        /* skip empty arrays */
        ; mov r13d, DWORD [object + 0x18]
        ; test r13, r13
        ; je =>exit_label

        /* loop init */
        ; lea object, [object + 0x20]
        ; xor r12, r12

        /* push comma starting with the second item */
        ;=>repeat_label

        /* serialize value */
        ; push object
        ;;let base_size = emit_calc_value(typ, 0, assembler)
        ; add buffer, base_size as _
        ; pop object

        /* move to next object and increment counter */
        ; add object, stride
        ; add r12, 1
        ; cmp r12, r13
        ; jb =>repeat_label

        /* commas */
        ; add buffer, r13
        ; sub buffer, 1

        ;=>exit_label
        ; pop r13
        ; pop r12
        ; pop object
    );
}

unsafe fn emit_serialize_value(typ: *const MonoType, field_offset: i32, assembler: &mut Assembler) {
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
                ; mov temp, QWORD push_integer::<$ty> as _
                ; call temp
                ; add buffer, retval
            )
        };
    }

    match (*typ).typ {
        MonoTypeEnum::MONO_TYPE_BOOLEAN => {
            emit_boolean(field_offset, assembler);
        }
        MonoTypeEnum::MONO_TYPE_CHAR => {
            utf16::emit_char(field_offset, assembler);
        }
        MonoTypeEnum::MONO_TYPE_I1 => {
            emit_integer!(i8, field_offset, movsx, edi, BYTE, assembler);
        }
        MonoTypeEnum::MONO_TYPE_I2 => {
            emit_integer!(i16, field_offset, movsx, edi, WORD, assembler);
        }
        MonoTypeEnum::MONO_TYPE_I4 => {
            emit_integer!(i32, field_offset, mov, edi, DWORD, assembler);
        }
        /* FIXME: So far, we're only running on 64 bit */
        MonoTypeEnum::MONO_TYPE_I8 | MonoTypeEnum::MONO_TYPE_I => {
            emit_integer!(i64, field_offset, mov, rdi, QWORD, assembler);
        }
        MonoTypeEnum::MONO_TYPE_U1 => {
            emit_integer!(u8, field_offset, movzx, edi, BYTE, assembler);
        }
        MonoTypeEnum::MONO_TYPE_U2 => {
            emit_integer!(u16, field_offset, movzx, edi, WORD, assembler);
        }
        MonoTypeEnum::MONO_TYPE_U4 => {
            emit_integer!(u32, field_offset, mov, edi, DWORD, assembler);
        }
        /* FIXME: So far, we're only running on 64 bit */
        MonoTypeEnum::MONO_TYPE_U8 | MonoTypeEnum::MONO_TYPE_U => {
            emit_integer!(u64, field_offset, mov, rdi, QWORD, assembler);
        }
        MonoTypeEnum::MONO_TYPE_R4 => {
            json_dynasm!(assembler
                ; movss xmm0, DWORD [object + field_offset]

                /* Check for 0.0 */
                ; xorps xmm1, xmm1
                ; ucomiss xmm0, xmm1
                ; jne >some
                ; jp >some
                ;;emit_string_copy("0.0", assembler)
                ; jmp >end

                ;some:
                ; mov rdi, buffer
                ; mov temp, QWORD push_float::<f32> as _
                ; call temp
                ; add buffer, retval

                ;end:
            );
        }
        MonoTypeEnum::MONO_TYPE_R8 => {
            json_dynasm!(assembler
                ; movsd xmm0, QWORD [object + field_offset]

                /* Check for 0.0 */
                ; xorpd xmm1, xmm1
                ; ucomisd xmm0, xmm1
                ; jne >some
                ; jp >some
                ;;emit_string_copy("0.0\0", assembler)
                ; jmp >end

                ;some:
                ; mov rdi, buffer
                ; mov temp, QWORD push_float::<f64> as _
                ; call temp
                ; add buffer, retval

                ;end:
            );
        }
        MonoTypeEnum::MONO_TYPE_STRING => {
            if field_offset == 0 {
                json_dynasm!(assembler
                    ; mov rdi, QWORD [object]
                );
            } else {
                json_dynasm!(assembler
                    ; mov rdi, QWORD [object + field_offset]
                );
            }
            json_dynasm!(assembler
                ; test rdi, rdi
                ; je >null
                ; mov temp_32, [rdi + 0x10]
                ; test temp, temp
                ; je >null
                ;;emit_string_copy("\"", assembler)

                ; mov rsi, buffer
                ; mov temp, QWORD utf16::push_string as _
                ; call temp

                ; add buffer, retval
                ;;emit_string_copy("\"", assembler)
                ; jmp >exit
                ;null:
                ;;emit_string_copy("\"\"", assembler)
                ;exit:
            );
        }
        MonoTypeEnum::MONO_TYPE_VALUETYPE => {
            json_dynasm!(assembler
                ; push object
                ; push object
            );

            if field_offset != 0x10 {
                json_dynasm!(assembler
                    ; lea object, [object + field_offset - 0x10]
                );
            }

            emit_serialize_class(&*(*typ).klass, assembler);

            json_dynasm!(assembler
                ; pop object
                ; pop object
            );
        }
        MonoTypeEnum::MONO_TYPE_CLASS => {
            let null_label = assembler.new_dynamic_label();
            json_dynasm!(assembler
                ; push object
                ; push object

                ; mov object, [object + field_offset]
                ; test object, object
                ; je =>null_label

                ;;emit_serialize_class(&*(*typ).klass, assembler)
                ; jmp >exit
                ;=>null_label
                ;;emit_string_copy("null", assembler)

                ;exit:
                ; pop object
                ; pop object
            );
        }
        MonoTypeEnum::MONO_TYPE_SZARRAY => {
            emit_array(field_offset, &*(*typ).klass, assembler);
        }
        _ => {
            emit_string_copy("null", assembler);
        }
    }
}

unsafe fn emit_serialize_class(klass: *const MonoClass, assembler: &mut Assembler) {
    let mut iter = ptr::null();
    let mut first = true;
    loop {
        let field = mono_class_get_fields(klass, &mut iter as _);
        if field.is_null() {
            break;
        }

        let typ = mono_field_get_type(field);
        let attrs = (*typ).attrs;
        // MONO_FIELD_ATTR_STATIC | MONO_FIELD_ATTR_NOT_SERIALIZED | MONO_FIELD_ATTR_PRIVATE
        if (attrs & 0x91) != 0 {
            continue;
        }

        let prefix = if first {
            first = false;
            '{'
        } else {
            ','
        };

        let cstr = CStr::from_ptr((*field).name as _);
        let string = if let Ok(name) = cstr.to_str() {
            format!("{prefix}\"{name}\":")
        } else {
            format!("{prefix}{cstr:?}:")
        };
        emit_string_copy(&string, assembler);

        emit_serialize_value(typ, (*field).offset, assembler);
    }

    emit_string_copy("}", assembler);
}

unsafe fn emit_calc_value(
    typ: *const MonoType,
    field_offset: i32,
    assembler: &mut Assembler,
) -> usize {
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
                ; mov temp, QWORD calc_integer_size::<$ty> as _
                ; call temp
                ; add buffer, retval
            )
        };
    }

    match (*typ).typ {
        MonoTypeEnum::MONO_TYPE_BOOLEAN => {
            json_dynasm!(assembler
                ; mov temp_8, BYTE [object + field_offset]
                ; sub buffer, temp
            );
            return 5;
        }
        MonoTypeEnum::MONO_TYPE_CHAR => {
            utf16::emit_char_length(field_offset, assembler);
            return 2;
        }
        MonoTypeEnum::MONO_TYPE_I1 => {
            emit_integer_size!(i8, field_offset, movsx, edi, BYTE, assembler);
        }
        MonoTypeEnum::MONO_TYPE_I2 => {
            emit_integer_size!(i16, field_offset, movsx, edi, WORD, assembler);
        }
        MonoTypeEnum::MONO_TYPE_I4 => {
            emit_integer_size!(i32, field_offset, mov, edi, DWORD, assembler);
        }
        /* FIXME: So far, we're only running on 64 bit */
        MonoTypeEnum::MONO_TYPE_I8 | MonoTypeEnum::MONO_TYPE_I => {
            emit_integer_size!(i64, field_offset, mov, rdi, QWORD, assembler);
        }
        MonoTypeEnum::MONO_TYPE_U1 => {
            emit_integer_size!(u8, field_offset, movzx, edi, BYTE, assembler);
        }
        MonoTypeEnum::MONO_TYPE_U2 => {
            emit_integer_size!(u16, field_offset, movzx, edi, WORD, assembler);
        }
        MonoTypeEnum::MONO_TYPE_U4 => {
            emit_integer_size!(u32, field_offset, mov, edi, DWORD, assembler);
        }
        /* FIXME: So far, we're only running on 64 bit */
        MonoTypeEnum::MONO_TYPE_U8 | MonoTypeEnum::MONO_TYPE_U => {
            emit_integer_size!(u64, field_offset, mov, rdi, QWORD, assembler);
        }
        MonoTypeEnum::MONO_TYPE_R4 => {
            json_dynasm!(assembler
                ; movss xmm0, DWORD [object + field_offset]

                /* Check for 0.0 */
                ; xorps xmm1, xmm1
                ; ucomiss xmm0, xmm1
                ; jne >some
                ; jp >some
                ; add buffer, 3
                ; jmp >end

                ;some:
                ; mov temp, QWORD calc_float_size::<f32> as _
                ; call temp
                ; add buffer, retval

                ;end:
            );
        }
        MonoTypeEnum::MONO_TYPE_R8 => {
            json_dynasm!(assembler
                ; movsd xmm0, QWORD [object + field_offset]

                /* Check for 0.0 */
                ; xorpd xmm1, xmm1
                ; ucomisd xmm0, xmm1
                ; jne >some
                ; jp >some
                ; add buffer, 3
                ; jmp >end

                ;some:
                ; mov temp, QWORD calc_float_size::<f64> as _
                ; call temp
                ; add buffer, retval

                ;end:
            );
        }
        MonoTypeEnum::MONO_TYPE_STRING => {
            if field_offset == 0 {
                json_dynasm!(assembler
                    ; mov rdi, QWORD [object]
                );
            } else {
                json_dynasm!(assembler
                    ; mov rdi, QWORD [object + field_offset]
                );
            }
            json_dynasm!(assembler
                ; test rdi, rdi
                ; je >null
                ; mov temp_32, [rdi + 0x10]
                ; test temp, temp
                ; je >null

                ;;utf16::emit_string_size(assembler)

                ;null:
            );
            return 2;
        }
        MonoTypeEnum::MONO_TYPE_VALUETYPE => {
            json_dynasm!(assembler
                ; push object
                ; push object
            );

            if field_offset != 0x10 {
                json_dynasm!(assembler
                    ; lea object, [object + field_offset - 0x10]
                );
            }

            let base_size = emit_calc_class(&*(*typ).klass, assembler);

            json_dynasm!(assembler
                ; pop object
                ; pop object
            );

            return base_size;
        }
        MonoTypeEnum::MONO_TYPE_CLASS => {
            let null_label = assembler.new_dynamic_label();
            json_dynasm!(assembler
                ; push object
                ; push object

                ; mov object, [object + field_offset]
                ; test object, object
                ; je =>null_label

                ;;let base_size = emit_calc_class(&*(*typ).klass, assembler)
                ; add buffer, base_size as _
                ; jmp >exit
                ;=>null_label
                ; add buffer, 4

                ;exit:
                ; pop object
                ; pop object
            );
        }
        MonoTypeEnum::MONO_TYPE_SZARRAY => {
            emit_array_size(field_offset, &*(*typ).klass, assembler);
            return 2;
        }
        _ => {
            return 4;
        }
    }
    0
}

unsafe fn emit_calc_class(klass: *const MonoClass, assembler: &mut Assembler) -> usize {
    let mut size = 0;

    let mut iter = ptr::null();
    loop {
        let field = mono_class_get_fields(klass, &mut iter as _);
        if field.is_null() {
            break;
        }

        let typ = mono_field_get_type(field);
        let attrs = (*typ).attrs;
        // MONO_FIELD_ATTR_STATIC | MONO_FIELD_ATTR_NOT_SERIALIZED | MONO_FIELD_ATTR_PRIVATE
        if (attrs & 0x91) != 0 {
            continue;
        }

        let cstr = CStr::from_ptr((*field).name as _);
        size += if let Ok(name) = cstr.to_str() {
            name.len() + "\"\":".len()
        } else {
            format!("{cstr:?}:").len()
        } + 1;

        size += emit_calc_value(typ, (*field).offset, assembler);
    }

    size + 1
}

#[no_mangle]
pub unsafe extern "C" fn emit_length(obj: *const MonoObject) -> *mut ExecutableBuffer {
    let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

    let klass = mono_object_get_class(obj);

    json_dynasm!(assembler
        /* store non-volatile registers */
        ; push object
        ; push buffer
        ; push rax

        ; xor buffer, buffer

        ; mov object, rdi
        ; test object, object
        ; je >null_root

        ;;let base_size = emit_calc_class(klass, &mut assembler)
        ; add buffer, base_size as _

        ; pop rax
        ; mov rax, buffer

        ; pop buffer
        ; pop object

        ; ret

        ;null_root:
        ; mov rax, "{}\0".len() as _

        /* restore non-volatile registers */
        ; pop rax
        ; pop buffer
        ; pop object

        ; ret
    );

    let block = assembler.finalize().unwrap();

    if cfg!(feature = "asm") {
        use std::io::prelude::*;

        let mut file = std::fs::File::create("asm_length.bin").unwrap();
        file.write_all(&block).unwrap();
    }

    Box::into_raw(Box::new(block))
}

#[no_mangle]
pub unsafe extern "C" fn emit(obj: *const MonoObject) -> *mut ExecutableBuffer {
    let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

    let klass = mono_object_get_class(obj);

    json_dynasm!(assembler
        /* store non-volatile registers */
        ; push object
        ; push buffer

        /* load arguments */
        ; mov object, rdi
        ; mov buffer, rsi

        /* store buffer start */
        ; push buffer

        ;;emit_serialize_class(klass, &mut assembler)

        /* Terminate string for further ffi */
        ; mov BYTE [buffer], '\0' as _

        /* Calculate buffer length */
        ; pop temp
        ; sub buffer, temp
        ; mov retval, buffer

        /* restore non-volatile registers */
        ; pop buffer
        ; pop object

        ; ret
    );

    let block = assembler.finalize().unwrap();

    if cfg!(feature = "asm") {
        use std::io::prelude::*;

        let mut file = std::fs::File::create("asm.bin").unwrap();
        file.write_all(&block).unwrap();
    }

    Box::into_raw(Box::new(block))
}

#[no_mangle]
pub unsafe extern "C" fn invoke(
    code: *const ExecutableBuffer,
    obj: *const MonoObject,
    buffer: *mut u8,
) -> usize {
    let ret: usize;

    asm!(
        "call rcx",

        in("rdi") obj,
        in("rsi") buffer,
        in("rcx") (*code).as_ptr(),
        out("rax") ret,

        clobber_abi("sysv64"),
    );

    ret
}

#[no_mangle]
pub unsafe extern "C" fn destroy(code: *mut ExecutableBuffer) {
    ptr::drop_in_place(code);
    alloc::dealloc(code as *mut u8, alloc::Layout::new::<ExecutableBuffer>());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{slice, str};

    macro_rules! newline {
        ($assembler:ident) => {
            emit_string_copy("\n", &mut $assembler)
        };
    }

    macro_rules! gen_test {
        ($value:expr, $exp:expr, $assembler:ident) => {
            json_dynasm!($assembler
                ; ret
            );

            let code = $assembler.finalize().unwrap();

            let mut buffer = vec![0u8; 0x1000];
            let mut offset: usize = buffer.as_mut_ptr() as usize;
            unsafe {
                asm!(
                    "call rcx",

                    in("rcx") code.as_ptr() as usize,
                    inout("r14") offset,
                    in("r15") $value
                );
                let length = offset - buffer.as_ptr() as usize;
                let slice = slice::from_raw_parts(buffer.as_ptr(), length);
                let string = str::from_utf8(slice).unwrap();

                assert_eq!($exp, string);
            }
        };
    }

    #[test]
    fn integers() {
        let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

        let value: &[i8] = &[i8::MIN, -1, 0, 1, i8::MAX];
        let width = 1;

        emit_integer!(i8, 0 * width, dil, BYTE, assembler);
        newline!(assembler);
        emit_integer!(i8, 1 * width, dil, BYTE, assembler);
        newline!(assembler);
        emit_integer!(i8, 2 * width, dil, BYTE, assembler);
        newline!(assembler);
        emit_integer!(i8, 3 * width, dil, BYTE, assembler);
        newline!(assembler);
        emit_integer!(i8, 4 * width, dil, BYTE, assembler);

        gen_test!(value.as_ptr() as usize, "-128\n-1\n0\n1\n127", assembler);

        let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

        let value: &[i16] = &[i16::MIN, -1, 0, 1, i16::MAX];
        let width = 2;

        emit_integer!(i16, 0 * width, di, WORD, assembler);
        newline!(assembler);
        emit_integer!(i16, 1 * width, di, WORD, assembler);
        newline!(assembler);
        emit_integer!(i16, 2 * width, di, WORD, assembler);
        newline!(assembler);
        emit_integer!(i16, 3 * width, di, WORD, assembler);
        newline!(assembler);
        emit_integer!(i16, 4 * width, di, WORD, assembler);

        gen_test!(
            value.as_ptr() as usize,
            "-32768\n-1\n0\n1\n32767",
            assembler
        );

        let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

        let value: &[i32] = &[i32::MIN, -1, 0, 1, i32::MAX];
        let width = 4;

        emit_integer!(i32, 0 * width, edi, DWORD, assembler);
        newline!(assembler);
        emit_integer!(i32, 1 * width, edi, DWORD, assembler);
        newline!(assembler);
        emit_integer!(i32, 2 * width, edi, DWORD, assembler);
        newline!(assembler);
        emit_integer!(i32, 3 * width, edi, DWORD, assembler);
        newline!(assembler);
        emit_integer!(i32, 4 * width, edi, DWORD, assembler);

        gen_test!(
            value.as_ptr() as usize,
            "-2147483648\n-1\n0\n1\n2147483647",
            assembler
        );

        let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

        let value: &[i64] = &[i64::MIN, -1, 0, 1, i64::MAX];
        let width = 8;

        emit_integer!(i64, 0 * width, rdi, QWORD, assembler);
        newline!(assembler);
        emit_integer!(i64, 1 * width, rdi, QWORD, assembler);
        newline!(assembler);
        emit_integer!(i64, 2 * width, rdi, QWORD, assembler);
        newline!(assembler);
        emit_integer!(i64, 3 * width, rdi, QWORD, assembler);
        newline!(assembler);
        emit_integer!(i64, 4 * width, rdi, QWORD, assembler);

        gen_test!(
            value.as_ptr() as usize,
            "-9223372036854775808\n-1\n0\n1\n9223372036854775807",
            assembler
        );

        let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

        let value: &[u8] = &[u8::MIN, 42, u8::MAX];
        let width = 1;

        emit_integer!(u8, 0 * width, dil, BYTE, assembler);
        newline!(assembler);
        emit_integer!(u8, 1 * width, dil, BYTE, assembler);
        newline!(assembler);
        emit_integer!(u8, 2 * width, dil, BYTE, assembler);

        gen_test!(value.as_ptr() as usize, "0\n42\n255", assembler);

        let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

        let value: &[u16] = &[u16::MIN, 1337, u16::MAX];
        let width = 2;

        emit_integer!(u16, 0 * width, di, WORD, assembler);
        newline!(assembler);
        emit_integer!(u16, 1 * width, di, WORD, assembler);
        newline!(assembler);
        emit_integer!(u16, 2 * width, di, WORD, assembler);

        gen_test!(value.as_ptr() as usize, "0\n1337\n65535", assembler);

        let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

        let value: &[u32] = &[u32::MIN, 1337, u32::MAX];
        let width = 4;

        emit_integer!(u32, 0 * width, edi, DWORD, assembler);
        newline!(assembler);
        emit_integer!(u32, 1 * width, edi, DWORD, assembler);
        newline!(assembler);
        emit_integer!(u32, 2 * width, edi, DWORD, assembler);

        gen_test!(value.as_ptr() as usize, "0\n1337\n4294967295", assembler);

        let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

        let value: &[u64] = &[u64::MIN, 1337, u64::MAX];
        let width = 8;

        emit_integer!(u64, 0 * width, rdi, QWORD, assembler);
        newline!(assembler);
        emit_integer!(u64, 1 * width, rdi, QWORD, assembler);
        newline!(assembler);
        emit_integer!(u64, 2 * width, rdi, QWORD, assembler);

        gen_test!(
            value.as_ptr() as usize,
            "0\n1337\n18446744073709551615",
            assembler
        );
    }

    #[test]
    fn floats() {
        let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

        let value: &[f32] = &[
            0.0,
            0.12345,
            1.2345,
            12.345,
            123.45,
            1234.5,
            12345.0,
            f32::NAN,
            f32::INFINITY,
            f32::NEG_INFINITY,
        ];

        emit_float(0 * 4, &mut assembler);
        newline!(assembler);
        emit_float(1 * 4, &mut assembler);
        newline!(assembler);
        emit_float(2 * 4, &mut assembler);
        newline!(assembler);
        emit_float(3 * 4, &mut assembler);
        newline!(assembler);
        emit_float(4 * 4, &mut assembler);
        newline!(assembler);
        emit_float(5 * 4, &mut assembler);
        newline!(assembler);
        emit_float(6 * 4, &mut assembler);
        newline!(assembler);
        emit_float(7 * 4, &mut assembler);
        newline!(assembler);
        emit_float(8 * 4, &mut assembler);
        newline!(assembler);
        emit_float(9 * 4, &mut assembler);

        gen_test!(
            value.as_ptr() as usize,
            "0.0\n0.12345\n1.2345\n12.345\n123.45\n1234.5\n12345.0\nNaN\ninf\n-inf",
            assembler
        );
    }

    #[test]
    fn doubles() {
        let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

        let value: &[f64] = &[
            0.0,
            0.12345,
            1.2345,
            12.345,
            123.45,
            1234.5,
            12345.0,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ];

        emit_double(0 * 8, &mut assembler);
        newline!(assembler);
        emit_double(1 * 8, &mut assembler);
        newline!(assembler);
        emit_double(2 * 8, &mut assembler);
        newline!(assembler);
        emit_double(3 * 8, &mut assembler);
        newline!(assembler);
        emit_double(4 * 8, &mut assembler);
        newline!(assembler);
        emit_double(5 * 8, &mut assembler);
        newline!(assembler);
        emit_double(6 * 8, &mut assembler);
        newline!(assembler);
        emit_double(7 * 8, &mut assembler);
        newline!(assembler);
        emit_double(8 * 8, &mut assembler);
        newline!(assembler);
        emit_double(9 * 8, &mut assembler);

        gen_test!(
            value.as_ptr() as usize,
            "0.0\n0.12345\n1.2345\n12.345\n123.45\n1234.5\n12345.0\nNaN\ninf\n-inf",
            assembler
        );
    }

    #[test]
    fn strings() {
        let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

        emit_string_copy("Some random longer string", &mut assembler);
        newline!(assembler);
        emit_string_copy("1", &mut assembler);
        newline!(assembler);
        emit_string_copy("12", &mut assembler);
        newline!(assembler);
        emit_string_copy("123", &mut assembler);
        newline!(assembler);
        emit_string_copy("1234", &mut assembler);
        newline!(assembler);
        emit_string_copy("12345", &mut assembler);
        newline!(assembler);
        emit_string_copy("123456", &mut assembler);
        newline!(assembler);
        emit_string_copy("1234567", &mut assembler);

        gen_test!(
            0 as usize,
            "Some random longer string\n1\n12\n123\n1234\n12345\n123456\n1234567",
            assembler
        );
    }
}
