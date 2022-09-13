use crate::{
    emit_calc_value, emit_serialize_value, json_dynasm, mono::*, strings::emit_string_copy,
    Assembler,
};
use dynasmrt::*;

pub unsafe fn emit_szarray(field_offset: i32, eclass: *const MonoClass, assembler: &mut Assembler) {
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
        ; add r12, BYTE 1
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

pub unsafe fn emit_szarray_size(
    field_offset: i32,
    eclass: *const MonoClass,
    assembler: &mut Assembler,
) {
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
        ; add r12, BYTE 1
        ; cmp r12, r13
        ; jb =>repeat_label

        /* commas */
        ; add buffer, r13
        ; sub buffer, BYTE 1

        ;=>exit_label
        ; pop r13
        ; pop r12
        ; pop object
    );
}
