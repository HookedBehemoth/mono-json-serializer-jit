use crate::{json_dynasm, strings::emit_string_copy, Assembler};

use dynasmrt::*;

pub unsafe fn emit_boolean(field_offset: i32, assembler: &mut Assembler) {
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
