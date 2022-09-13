mod array;
mod boolean;
mod float;
mod integer;
mod mono;
mod strings;
mod utf16_to_utf8;

use array::{emit_szarray, emit_szarray_size};
use boolean::emit_boolean;
use mono::*;
use dynasmrt::*;
use float::{emit_f32, emit_f32_size, emit_f64, emit_f64_size};
use strings::emit_string_copy;
use utf16_to_utf8::{emit_char, emit_char_length, emit_string, emit_string_size};

use std::{alloc, arch::asm, ffi::CStr, ptr};

#[macro_export]
macro_rules! json_dynasm {
    ($ops:ident $($t:tt)*) => {
        dynasmrt::dynasm!($ops
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

pub type Assembler = dynasmrt::Assembler<x64::X64Relocation>;

unsafe fn emit_serialize_value(typ: *const MonoType, field_offset: i32, assembler: &mut Assembler) {
    match (*typ).typ {
        MonoTypeEnum::MONO_TYPE_BOOLEAN => {
            emit_boolean(field_offset, assembler);
        }
        MonoTypeEnum::MONO_TYPE_CHAR => {
            emit_char(field_offset, assembler);
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
            emit_f32(field_offset, assembler);
        }
        MonoTypeEnum::MONO_TYPE_R8 => {
            emit_f64(field_offset, assembler);
        }
        MonoTypeEnum::MONO_TYPE_STRING => {
            emit_string(field_offset, assembler);
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
                ; jmp BYTE >exit
                ;=>null_label
                ;;emit_string_copy("null", assembler)

                ;exit:
                ; pop object
                ; pop object
            );
        }
        MonoTypeEnum::MONO_TYPE_SZARRAY => {
            emit_szarray(field_offset, &*(*typ).klass, assembler);
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
    match (*typ).typ {
        MonoTypeEnum::MONO_TYPE_BOOLEAN => {
            json_dynasm!(assembler
                ; mov temp_8, BYTE [object + field_offset]
                ; sub buffer, temp
            );
            return 5;
        }
        MonoTypeEnum::MONO_TYPE_CHAR => {
            emit_char_length(field_offset, assembler);
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
            emit_f32_size(field_offset, assembler);
        }
        MonoTypeEnum::MONO_TYPE_R8 => {
            emit_f64_size(field_offset, assembler);
        }
        MonoTypeEnum::MONO_TYPE_STRING => {
            emit_string_size(field_offset, assembler);
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
                ; jmp BYTE >exit
                ;=>null_label
                ; add buffer, BYTE 4

                ;exit:
                ; pop object
                ; pop object
            );
        }
        MonoTypeEnum::MONO_TYPE_SZARRAY => {
            emit_szarray_size(field_offset, &*(*typ).klass, assembler);
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
