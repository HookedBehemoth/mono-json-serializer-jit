mod mono;

use dynasmrt::*;
use mono::*;

use std::{alloc, mem, ops::Shl, ptr};

/*
extern "C" {
    /// Provided by libc or compiler_builtins.
    fn strlen(s: *const u8) -> usize;
}
*/

macro_rules! json_dynasm {
    ($ops:ident $($t:tt)*) => {
        dynasm!($ops
            ; .arch x64
            /* r15: object, r14: buffer, r13: offset */
            ; .alias object, r15
            ; .alias buffer, r14
            ; .alias offset, r13

            ; .alias temp, r12
            ; .alias temp_32, r12d
            ; .alias temp_16, r12w
            ; .alias temp_8, r12b
            // return code/return bytecode pc
            ; .alias retval, rax
            ; .alias retval_32, eax
            ; .alias retval_8, al
            $($t)*
        )
    }
}

unsafe fn push_utf16(s: *const MonoString, dst: *mut u8) -> usize {
    let length =
        simdutf::convert_valid_utf16le_to_utf8(&(*s).chars as *const u16, (*s).length as _, dst);
    length
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
            ; lea rsi, [buffer + offset]
            ; mov rax, QWORD push_integer::<$ty> as _
            ; call rax
            ; add offset, retval
            ; pop rdi
        )
    };
}

fn emit_null(assembler: &mut Assembler<x64::X64Relocation>) {
    json_dynasm!(assembler
        ; mov DWORD [buffer + offset], 0x6C6C756E
        ; add offset, 4
    );
}

fn emit_string_copy(string: &str, assembler: &mut Assembler<x64::X64Relocation>) {
    fn pack4(s: &[u8], off: usize) -> u32 {
        (s[off + 3] as u32).shl(0x18) as u32
            | (s[off + 2] as u32).shl(0x10) as u32
            | (s[off + 1] as u32).shl(0x08) as u32
            | (s[off + 0] as u32).shl(0x00) as u32
    }
    fn pack2(s: &[u8], off: usize) -> u16 {
        (s[off + 1] as u16).shl(0x08) as u16
        | (s[off + 0] as u16).shl(0x00) as u16
    }

    let s: &[u8] = string.as_bytes();
    if s.len() > 4 {
        let mut off: usize = 0;
        while (off + 4) < s.len() {
            let value = pack4(s, off);
            // println!("{} -> {:X}", &string[off..off + 4], value);
            json_dynasm!(assembler
                ; mov DWORD [buffer + offset + off as _], value as _
            );
            off += 4
        }
        if off < s.len() {
            let start = s.len() - 4;
            let value = pack4(s, start);
            // println!("{} -> {:X}", &string[start..s.len()], value);
            json_dynasm!(assembler
                ; mov DWORD [buffer + offset + start as _], value as _
            );
        }
    } else if s.len() == 4 {
        let value = pack4(s, 0);
        json_dynasm!(assembler
            ; mov DWORD [buffer + offset], value as _
        );
    } else if s.len() == 3 {
        let value = pack2(s, 0);
        json_dynasm!(assembler
            ; mov WORD [buffer + offset], value as _
            ; mov BYTE [buffer + offset + 2], s[2] as _
        );
    } else if s.len() == 2 {
        let value = pack2(s, 0);
        json_dynasm!(assembler
            ; mov WORD [buffer + offset], value as _
        );
    } else {
        json_dynasm!(assembler
            ; mov BYTE [buffer + offset], s[0] as _
        );
    }
    json_dynasm!(assembler
        ; add offset, s.len() as _
    );
}

unsafe fn emit_serialize_value(
    typ: *const MonoType,
    field_offset: i32,
    assembler: &mut Assembler<x64::X64Relocation>,
) {
    match (*typ).typ {
        MonoTypeEnum::MONO_TYPE_BOOLEAN => {
            json_dynasm!(assembler
                ; mov temp_8, BYTE [object + field_offset]
                ; test temp_8, temp_8
                ; je >not
                ; mov DWORD [buffer + offset], 0x65757274
                ; add offset, 4
                ; jmp >exit
                ;not:
                ; mov DWORD [buffer + offset], 0x736C6166
                ; mov DWORD [buffer + offset + 1], 0x65736C61
                ; add offset, 5
                ; exit:
            );
        }
        MonoTypeEnum::MONO_TYPE_CHAR => {
            emit_string_copy("\"", assembler);
            json_dynasm!(assembler
                ; lea rdi, [object + field_offset]
                ; mov rsi, 1
                ; lea rdx, [buffer + offset]
                ; push rax
                ; mov rax, QWORD simdutf::convert_valid_utf16le_to_utf8 as _
                ; call rax
                ; add offset, retval
                ; pop rax
            );
            emit_string_copy("\"", assembler);
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
            json_dynasm!(assembler
                ; push rdi
                ; movss xmm0, DWORD [object + field_offset]
                ; lea rdi, [buffer + offset]
                ; mov rax, QWORD push_float::<f32> as _
                ; call rax
                ; add offset, retval
                ; pop rdi
            );
        }
        MonoTypeEnum::MONO_TYPE_R8 => {
            json_dynasm!(assembler
                ; push rdi
                ; movsd xmm0, QWORD [object + field_offset]
                ; lea rdi, [buffer + offset]
                ; mov rax, QWORD push_float::<f64> as _
                ; call rax
                ; add offset, retval
                ; pop rdi
            );
        }
        MonoTypeEnum::MONO_TYPE_STRING => {
            let null_label = assembler.new_dynamic_label();
            json_dynasm!(assembler
                ; mov object, QWORD [object + field_offset]
                ; test object, object
                ; je =>null_label
            );
            emit_string_copy("\"", assembler);
            json_dynasm!(assembler
                ; mov rdi, object
                ; lea rsi, [buffer + offset]
                ; push rax
                ; mov rax, QWORD push_utf16 as _
                ; call rax
                ; add offset, retval
                ; pop rax
            );
            emit_string_copy("\"", assembler);
            json_dynasm!(assembler
                ; jmp >exit
                ;=>null_label
            );
            emit_null(assembler);
            assembler.local_label("exit");
        }
        MonoTypeEnum::MONO_TYPE_VALUETYPE => {
            json_dynasm!(assembler
                ; lea object, [object + field_offset - 0x10]
            );
            emit_serialize_class(&*(*typ).klass, assembler);
        }
        MonoTypeEnum::MONO_TYPE_CLASS => {
            let null_label = assembler.new_dynamic_label();
            json_dynasm!(assembler
                ; mov object, [object + field_offset]
                ; test object, object
                ; je =>null_label
            );
            emit_serialize_class(&*(*typ).klass, assembler);
            json_dynasm!(assembler
                ; jmp >exit
                ;=>null_label
            );
            emit_null(assembler);
            assembler.local_label("exit");
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

        if first {
            first = false;
        } else {
            emit_string_copy(",", assembler);
        }

        let ptr = (*field).name as *const u8;
        let string = format!("\"{}\":", std::ffi::CStr::from_ptr(ptr as _).to_str().unwrap());
        emit_string_copy(&string, assembler);

        json_dynasm!(assembler
            ; push object
        );

        emit_serialize_value(typ, (*field).offset, assembler);

        json_dynasm!(assembler
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

    json_dynasm!(assembler
        ; push rbx
        ; push rsp
        ; push rbp
        ; push r12
        ; push r13
        ; push r14
        ; push r15
        ; mov object, rdi
        ; mov buffer, rsi
        ; mov offset, BYTE 0
    );

    let klass = mono_object_get_class(obj);

    /*
    emit_string_copy(
        "VeryLongStringThatIJustMadeUpIdkWhyIMakeItSoLong133",
        &mut assembler,
    );

    emit_string_copy(
        "\n",
        &mut assembler,
    );

    emit_string_copy(
        "1",
        &mut assembler,
    );

    emit_string_copy(
        "\n",
        &mut assembler,
    );

    emit_string_copy(
        "12",
        &mut assembler,
    );

    emit_string_copy(
        "\n",
        &mut assembler,
    );

    emit_string_copy(
        "123",
        &mut assembler,
    );

    emit_string_copy(
        "\n",
        &mut assembler,
    );

    emit_string_copy(
        "1234",
        &mut assembler,
    );

    emit_string_copy(
        "\n",
        &mut assembler,
    );

    emit_string_copy(
        "12345",
        &mut assembler,
    );
    */

    
    emit_serialize_class(klass, &mut assembler);
    

    json_dynasm!(assembler
        ; mov retval, offset
        ; pop r15
        ; pop r14
        ; pop r13
        ; pop r12
        ; pop rbp
        ; pop rsp
        ; pop rbx
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
    let serialize: extern "cdecl" fn(obj: *const MonoObject, buffer: *mut u8) -> usize =
        mem::transmute((*code).as_ptr());
    serialize(obj, buffer)
}

#[no_mangle]
pub unsafe extern "C" fn destroy(code: *mut ExecutableBuffer) {
    ptr::drop_in_place(code);
    alloc::dealloc(code as *mut u8, alloc::Layout::new::<ExecutableBuffer>());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        unsafe {
            let code = emit(ptr::null());
            let result = invoke(code, ptr::null(), ptr::null_mut());
            assert_eq!(result, 42);
            destroy(code);
        }
    }
}
