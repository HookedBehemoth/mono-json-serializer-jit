mod mono;

use dynasmrt::*;
use mono::*;

use std::{alloc, arch::asm, ffi::CStr, ops::Shl, ptr};

macro_rules! json_dynasm {
    ($ops:ident $($t:tt)*) => {
        dynasm!($ops
            ; .arch x64

            ; .alias object, r15
            ; .alias buffer, r14

            ; .alias temp, r12
            ; .alias temp_32, r12d
            ; .alias temp_16, r12w
            ; .alias temp_8, r12b
            // return code/return bytecode pc
            ; .alias retval, rax
            $($t)*
        )
    }
}

unsafe fn emit_boolean(field_offset: i32, assembler: &mut Assembler<x64::X64Relocation>) {
    json_dynasm!(assembler
        ; mov temp_8, BYTE [object + field_offset]
        ; test temp_8, temp_8
        ; je >not
        ; mov DWORD [buffer], 0x65757274
        ; add buffer, 4
        ; jmp >exit
        ;not:
        ; mov DWORD [buffer], 0x736C6166
        ; mov DWORD [buffer + 1], 0x65736C61
        ; add buffer, 5
        ; exit:
    );
}

unsafe fn push_utf16(s: *const MonoString, dst: *mut u8) -> usize {
    if cfg!(feature = "utf") {
        simdutf::convert_valid_utf16le_to_utf8(&(*s).chars as *const u16, (*s).length as _, dst)
    } else {
        for i in 0..((*s).length as usize) {
            *dst.add(i) = *(&(*s).chars as *const u16).add(i) as _;
        }
        (*s).length as _
    }
}

unsafe fn push_float<F: ryu::Float + std::fmt::Display>(value: F, dst: *mut u8) -> usize {
    let mut buffer = ryu::Buffer::new();
    let printed = buffer.format(value);
    ptr::copy_nonoverlapping(printed.as_ptr(), dst, printed.len());
    printed.len()
}

unsafe fn push_integer<I: itoa::Integer + std::fmt::Display>(value: I, dst: *mut u8) -> usize {
    let mut buffer = itoa::Buffer::new();
    let printed = buffer.format(value);
    ptr::copy_nonoverlapping(printed.as_ptr(), dst, printed.len());
    printed.len()
}

macro_rules! emit_integer {
    ($ty:ty, $offset:expr, $reg:ident, $width:expr, $assembler:ident) => {
        json_dynasm!($assembler
            ; push rdi
            ; mov $reg, $width [object + $offset]
            ; mov rsi, buffer
            ; mov rax, QWORD push_integer::<$ty> as _
            ; call rax
            ; add buffer, retval
            ; pop rdi
        )
    };
}

fn emit_float(field_offset: i32, assembler: &mut Assembler<x64::X64Relocation>) {
    json_dynasm!(assembler
        ; movss xmm0, DWORD [object + field_offset]
        ; mov rdi, buffer
        ; mov rax, QWORD push_float::<f32> as _
        ; call rax
        ; add buffer, retval
    );
}

fn emit_double(field_offset: i32, assembler: &mut Assembler<x64::X64Relocation>) {
    json_dynasm!(assembler
        ; movsd xmm0, QWORD [object + field_offset]
        ; mov rdi, buffer
        ; mov rax, QWORD push_float::<f64> as _
        ; call rax
        ; add buffer, retval
    );
}

fn emit_null(assembler: &mut Assembler<x64::X64Relocation>) {
    json_dynasm!(assembler
        ; mov DWORD [buffer], 0x6C6C756E
        ; add buffer, 4
    );
}

/**
 * Pack strings into 32 and 16 bit moves instead of
 * looping over very string.
 */
fn emit_string_copy(string: &str, assembler: &mut Assembler<x64::X64Relocation>) {
    fn pack32(s: &[u8], off: usize) -> u32 {
        (s[off + 3] as u32).shl(0x18) as u32
            | (s[off + 2] as u32).shl(0x10) as u32
            | (s[off + 1] as u32).shl(0x08) as u32
            | (s[off + 0] as u32).shl(0x00) as u32
    }
    fn pack16(s: &[u8], off: usize) -> u16 {
        (s[off + 1] as u16).shl(0x08) as u16 | (s[off + 0] as u16).shl(0x00) as u16
    }

    let s: &[u8] = string.as_bytes();
    if s.len() >= 4 {
        let mut off: usize = 0;
        while (off + 4) < s.len() {
            let value = pack32(s, off);
            json_dynasm!(assembler
                ; mov DWORD [buffer + off as _], value as _
            );
            off += 4
        }
        if off < s.len() {
            let start = s.len() - 4;
            let value = pack32(s, start);
            json_dynasm!(assembler
                ; mov DWORD [buffer + start as _], value as _
            );
        }
    } else if s.len() == 3 {
        let value = pack16(s, 0);
        json_dynasm!(assembler
            ; mov WORD [buffer], value as _
            ; mov BYTE [buffer + 2], s[2] as _
        );
    } else if s.len() == 2 {
        let value = pack16(s, 0);
        json_dynasm!(assembler
            ; mov WORD [buffer], value as _
        );
    } else {
        json_dynasm!(assembler
            ; mov BYTE [buffer], s[0] as _
        );
    }
    json_dynasm!(assembler
        ; add buffer, s.len() as _
    );
}

unsafe fn emit_array(eclass: *const MonoClass, assembler: &mut Assembler<x64::X64Relocation>) {
    let stride = mono_class_array_element_size(eclass);
    let typ = mono_class_get_type(eclass);

    let empty_label = assembler.new_dynamic_label();
    let repeat_label = assembler.new_dynamic_label();
    json_dynasm!(assembler
        /* check for null */
        ; test object, object
        ; je =>empty_label

        /* skip empty arrays */
        ; mov edi, DWORD [object + 0x18]
        ; test rdi, rdi
        ; je =>empty_label

        ;;emit_string_copy("[", assembler)

        /* loop init */
        ; lea object, [object + 0x20]
        ; xor rsi, rsi
        ; jmp >push

        /* push comma starting with the second item */
        ;=>repeat_label
        ;;emit_string_copy(",", assembler)

        /* serialize value */
        ;push:
        ; push object
        ; push rdi
        ; push rsi
        ;;emit_serialize_value(typ, 0, assembler)
        ; pop rsi
        ; pop rdi
        ; pop object

        /* move to next object and increment counter */
        ; add object, stride
        ; add rsi, 1
        ; cmp rsi, rdi
        ; jb =>repeat_label

        ;;emit_string_copy("]", assembler)
        ; jmp >exit

        /* push empty array */
        ;=>empty_label
        ;;emit_string_copy("[]", assembler)

        ;exit:
    );
}

unsafe fn emit_serialize_value(
    typ: *const MonoType,
    field_offset: i32,
    assembler: &mut Assembler<x64::X64Relocation>,
) {
    match (*typ).typ {
        MonoTypeEnum::MONO_TYPE_BOOLEAN => {
            emit_boolean(field_offset, assembler);
        }
        MonoTypeEnum::MONO_TYPE_CHAR => {
            if cfg!(feature = "utf") {
                json_dynasm!(assembler
                    ;;emit_string_copy("\"", assembler)
                    ; lea rdi, [object + field_offset]
                    ; mov rsi, 1
                    ; mov rdx, buffer
                    ; push rax
                    ; mov rax, QWORD simdutf::convert_valid_utf16le_to_utf8 as _
                    ; call rax
                    ; add buffer, retval
                    ; pop rax
                    ;;emit_string_copy("\"", assembler)
                );
            } else {
                json_dynasm!(assembler
                    ;;emit_string_copy("\"", assembler)
                    ; mov temp_8, [object + field_offset]
                    ; mov BYTE [buffer], temp_8
                    ; add buffer, 1
                    ;;emit_string_copy("\"", assembler)
                );
            }
        }
        MonoTypeEnum::MONO_TYPE_I1 => {
            emit_integer!(i8, field_offset, dil, BYTE, assembler);
        }
        MonoTypeEnum::MONO_TYPE_I2 => {
            emit_integer!(i16, field_offset, di, WORD, assembler);
        }
        MonoTypeEnum::MONO_TYPE_I4 => {
            emit_integer!(i32, field_offset, edi, DWORD, assembler);
        }
        /* FIXME: So far, we're only running on 64 bit */
        MonoTypeEnum::MONO_TYPE_I8 | MonoTypeEnum::MONO_TYPE_I => {
            emit_integer!(i64, field_offset, rdi, QWORD, assembler);
        }
        MonoTypeEnum::MONO_TYPE_U1 => {
            emit_integer!(u8, field_offset, dil, BYTE, assembler);
        }
        MonoTypeEnum::MONO_TYPE_U2 => {
            emit_integer!(u16, field_offset, di, WORD, assembler);
        }
        MonoTypeEnum::MONO_TYPE_U4 => {
            emit_integer!(u32, field_offset, edi, DWORD, assembler);
        }
        /* FIXME: So far, we're only running on 64 bit */
        MonoTypeEnum::MONO_TYPE_U8 | MonoTypeEnum::MONO_TYPE_U => {
            emit_integer!(u64, field_offset, rdi, QWORD, assembler);
        }
        MonoTypeEnum::MONO_TYPE_R4 => {
            emit_float(field_offset, assembler);
        }
        MonoTypeEnum::MONO_TYPE_R8 => {
            emit_double(field_offset, assembler);
        }
        MonoTypeEnum::MONO_TYPE_STRING => {
            json_dynasm!(assembler
                ; mov object, QWORD [object + field_offset]
                ; test object, object
                ; je >null
                ;;emit_string_copy("\"", assembler)
                ; mov rdi, object
                ; mov rsi, buffer
                ; push rax
                ; mov rax, QWORD push_utf16 as _
                ; call rax
                ; add buffer, retval
                ; pop rax
                ;;emit_string_copy("\"", assembler)
                ; jmp >exit
                ;null:
                ;;emit_null(assembler)
                ;exit:
            );
        }
        MonoTypeEnum::MONO_TYPE_VALUETYPE => {
            json_dynasm!(assembler
                ; lea object, [object + field_offset - 0x10]
                ;;emit_serialize_class(&*(*typ).klass, assembler)
            );
        }
        MonoTypeEnum::MONO_TYPE_CLASS => {
            let null_label = assembler.new_dynamic_label();
            json_dynasm!(assembler
                ; mov object, [object + field_offset]
                ; test object, object
                ; je =>null_label
                ;;emit_serialize_class(&*(*typ).klass, assembler)
                ; jmp >exit
                ;=>null_label
                ;;emit_null(assembler)
                ;exit:
            );
        }
        MonoTypeEnum::MONO_TYPE_SZARRAY => {
            json_dynasm!(assembler
                ; mov object, [object + field_offset]
                ;;emit_array(&*(*typ).klass, assembler)
            );
        }
        _ => {
            emit_null(assembler);
        }
    }
}

unsafe fn emit_serialize_class(
    klass: *const MonoClass,
    assembler: &mut Assembler<x64::X64Relocation>,
) {
    emit_string_copy("{", assembler);

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
            ""
        } else {
            ","
        };

        let cstr = CStr::from_ptr((*field).name as _);
        let string = if let Ok(name) = cstr.to_str() {
            format!("{prefix}\"{name}\":")
        } else {
            format!("{prefix}{cstr:?}:")
        };
        emit_string_copy(&string, assembler);

        json_dynasm!(assembler
            ; push object
            ;;emit_serialize_value(typ, (*field).offset, assembler)
            ; pop object
        );
    }

    emit_string_copy("}", assembler);
}

#[no_mangle]
pub unsafe extern "C" fn emit_length(obj: *const MonoObject) -> *mut ExecutableBuffer {
    let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

    json_dynasm!(assembler
        ; mov object, rdi
    );

    let _ = obj;

    let code_length = assembler.offset().0;

    let block = assembler.finalize().unwrap();

    {
        use std::io::prelude::*;

        let mut file = std::fs::File::create("asm.bin").unwrap();
        file.write_all(&(&block as &[u8])[..code_length]).unwrap();
    }

    Box::into_raw(Box::new(block))
}

#[no_mangle]
pub unsafe extern "C" fn emit(obj: *const MonoObject) -> *mut ExecutableBuffer {
    let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

    let klass = mono_object_get_class(obj);

    json_dynasm!(assembler
        /* Store buffer start */
        ; push buffer
        ;;emit_serialize_class(klass, &mut assembler)
        ; mov BYTE [buffer], '\0' as _
        /* Calculate buffer length */
        ; pop rsi
        ; sub buffer, rsi
        ; mov retval, buffer
        ; ret
    );

    let code_length = assembler.offset().0;

    let block = assembler.finalize().unwrap();

    {
        use std::io::prelude::*;

        let mut file = std::fs::File::create("asm.bin").unwrap();
        file.write_all(&(&block as &[u8])[..code_length]).unwrap();
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

        in("r14") buffer,
        in("r15") obj,
        in("rcx") (*code).as_ptr(),
        out("rax") ret,
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
    fn null() {
        let mut assembler = dynasmrt::x64::Assembler::new().unwrap();

        emit_null(&mut assembler);

        gen_test!(0 as usize, "null", assembler);
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
