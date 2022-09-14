use crate::{json_dynasm, strings::emit_string_copy, Assembler};
use dynasmrt::*;

pub unsafe extern "sysv64" fn push_f32(value: f32, dst: *mut u8) -> usize {
    ryu::raw::format32(value, dst)
}

pub unsafe extern "sysv64" fn push_f64(value: f64, dst: *mut u8) -> usize {
    ryu::raw::format64(value, dst)
}

pub unsafe extern "sysv64" fn calc_float_size<F: ryu::Float + std::fmt::Display>(value: F) -> usize {
    let mut buffer = ryu::Buffer::new();
    let printed = buffer.format(value);
    printed.len()
}

pub fn emit_f32_size(field_offset: i32, assembler: &mut Assembler) {
    json_dynasm!(assembler
        ; movss xmm0, DWORD [object + field_offset]

        /* Check for 0.0 */
        ; xorps xmm1, xmm1
        ; ucomiss xmm0, xmm1
        ; jne BYTE >some
        ; jp BYTE >some
        ; add buffer, BYTE 3
        ; jmp BYTE >end

        ;some:
        ; mov temp, QWORD crate::float::calc_float_size::<f32> as _
        ; call temp
        ; add buffer, retval

        ;end:
    );
}

pub fn emit_f64_size(field_offset: i32, assembler: &mut Assembler) {
    json_dynasm!(assembler
        ; movsd xmm0, QWORD [object + field_offset]

        /* Check for 0.0 */
        ; xorpd xmm1, xmm1
        ; ucomisd xmm0, xmm1
        ; jne BYTE >some
        ; jp BYTE >some
        ; add buffer, BYTE 3
        ; jmp BYTE >end

        ;some:
        ; mov temp, QWORD calc_float_size::<f64> as _
        ; call temp
        ; add buffer, retval

        ;end:
    );
}

pub fn emit_f32(field_offset: i32, assembler: &mut Assembler) {
    json_dynasm!(assembler
        ; movss xmm0, DWORD [object + field_offset]

        /* Check for 0.0 */
        ; xorps xmm1, xmm1
        ; ucomiss xmm0, xmm1
        ; jne BYTE >some
        ; jp BYTE >some
        ;;emit_string_copy("0.0", assembler)
        ; jmp BYTE >end

        ;some:
        ; mov rdi, buffer
        ; mov temp, QWORD push_f32 as _
        ; call temp
        ; add buffer, retval

        ;end:
    );
}

pub fn emit_f64(field_offset: i32, assembler: &mut Assembler) {
    json_dynasm!(assembler
        ; movsd xmm0, QWORD [object + field_offset]

        /* Check for 0.0 */
        ; xorpd xmm1, xmm1
        ; ucomisd xmm0, xmm1
        ; jne BYTE >some
        ; jp BYTE >some
        ;;emit_string_copy("0.0", assembler)
        ; jmp BYTE >end

        ;some:
        ; mov rdi, buffer
        ; mov temp, QWORD push_f64 as _
        ; call temp
        ; add buffer, retval

        ;end:
    );
}
