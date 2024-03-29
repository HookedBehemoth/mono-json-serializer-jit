use crate::{json_dynasm, strings::emit_string_copy, Assembler};

use dynasmrt::*;

const ESCAPE: [u8; 256] = [
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x62, 0x74, 0x6e, 0x75, 0x66, 0x72, 0x75,
    0x75, // 00
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,
    0x75, // 10
    0, 0, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 20
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 30
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 40
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x5c, 0, 0, 0, // 50
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 60
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 70
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 80
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 90
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // a0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // b0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // c0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // d0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // e0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // f0
];

const ESCAPE_LENGTH: [usize; 256] = [
    6, 6, 6, 6, 6, 6, 6, 6, 2, 2, 2, 6, 2, 2, 6, 6, // 00
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, // 10
    1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 20
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 30
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 40
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, // 50
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 60
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 70
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 80
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 90
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // a0
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // b0
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // c0
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // d0
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // e0
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // f0
];

const HEXDIGITS: [u8; 16] = [
    '0' as u8, '1' as u8, '2' as u8, '3' as u8, '4' as u8, '5' as u8, '6' as u8, '7' as u8,
    '8' as u8, '9' as u8, 'A' as u8, 'B' as u8, 'C' as u8, 'D' as u8, 'E' as u8, 'F' as u8,
];

unsafe fn escape_char(byte: u8, dst: *mut u8) -> usize {
    let escape = ESCAPE[byte as usize];
    if escape != 0 {
        *dst.add(0) = '\\' as u8;
        *dst.add(1) = escape;
        if escape == 'u' as u8 {
            *dst.add(2) = '0' as u8;
            *dst.add(3) = '0' as u8;
            *dst.add(4) = HEXDIGITS[(byte >> 4) as usize] as u8;
            *dst.add(5) = HEXDIGITS[(byte & 0xf) as usize] as u8;
            6
        } else {
            2
        }
    } else {
        *dst = byte;
        1
    }
}

fn calc_char_size(byte: u8) -> usize {
    ESCAPE_LENGTH[byte as usize]
}

unsafe extern "sysv64" fn push_string(data: *const u16, len: usize, dst: *mut u8) -> usize {
    let mut pos = 0;
    let mut utf8_output = dst;

    while pos < len {
        if pos + 4 <= len {
            let mut bytes = [0u8; 8];
            std::ptr::copy_nonoverlapping(data.add(pos) as *const u8, bytes.as_mut_ptr(), 8);
            let v = u64::from_le_bytes(bytes);
            if (v & 0xff80ff80ff80ff80) == 0 {
                for i in pos..pos + 4 {
                    let byte = (*data.add(i) & 0x7f) as u8;
                    let length = escape_char(byte, utf8_output);
                    utf8_output = utf8_output.add(length);
                }
                pos += 4;
                continue;
            }
        }
        let word = *data.add(pos);
        if (word & 0xFF80) == 0 {
            let byte = (word & 0x7f) as u8;
            let length = escape_char(byte, utf8_output);
            utf8_output = utf8_output.add(length);
            pos += 1;
        } else if (word & 0xf800) == 0 {
            // will generate two UTF-8 bytes
            // we have 0b110XXXXX 0b10XXXXXX
            *utf8_output.add(0) = (((word >> 6) | 0b11000000) & 0xff) as u8;
            *utf8_output.add(1) = (((word & 0b111111) | 0b10000000) & 0xff) as u8;
            utf8_output = utf8_output.add(2);
            pos += 1;
        } else if (word & 0xf800) != 0xd800 {
            // will generate three UTF-8 bytes
            // we have 0b1110XXXX 0b10XXXXXX 0b10XXXXXX
            *utf8_output.add(0) = (((word >> 12) | 0b11100000) & 0xff) as u8;
            *utf8_output.add(1) = ((((word >> 6) & 0b111111) | 0b10000000) & 0xff) as u8;
            *utf8_output.add(2) = (((word & 0b111111) | 0b10000000) & 0xff) as u8;
            utf8_output = utf8_output.add(3);
            pos += 1;
        } else {
            if pos + 1 > len {
                return 0;
            }
            let diff = word - 0xd800;
            if diff > 0x3ff {
                return 0;
            }
            let next_word = *data.add(pos + 1);
            let diff2 = next_word - 0xdc00;
            if diff2 > 0x3ff {
                return 0;
            }
            let value = ((diff as u32) << 10) + (diff2 as u32) + 0x10000;
            // will generate four UTF-8 bytes
            // we have 0b11110XXX 0b10XXXXXX 0b10XXXXXX 0b10XXXXXX
            *utf8_output.add(0) = (((value >> 18) | 0b11110000) & 0xff) as u8;
            *utf8_output.add(1) = ((((value >> 12) & 0b111111) | 0b10000000) & 0xff) as u8;
            *utf8_output.add(2) = ((((value >> 6) & 0b111111) | 0b10000000) & 0xff) as u8;
            *utf8_output.add(3) = (((value & 0b111111) | 0b10000000) & 0xff) as u8;
            utf8_output = utf8_output.add(4);
            pos += 2;
        }
    }

    (utf8_output as usize) - (dst as usize)
}

unsafe extern "sysv64" fn calc_string_size(data: *const u16, len: usize) -> usize {
    let mut pos = 0;
    let mut size = 0;

    while pos < len {
        if pos + 4 <= len {
            let mut bytes = [0u8; 8];
            std::ptr::copy_nonoverlapping(data.add(pos) as *const u8, bytes.as_mut_ptr(), 8);
            let v = u64::from_le_bytes(bytes);
            if (v & 0xff80ff80ff80ff80) == 0 {
                for i in pos..pos + 4 {
                    let byte = (*data.add(i) & 0x7f) as u8;
                    size += calc_char_size(byte);
                }
                pos += 4;
                continue;
            }
        }
        let word = *data.add(pos);
        if (word & 0xFF80) == 0 {
            size += calc_char_size((word & 0x7f) as u8);
            pos += 1;
        } else if (word & 0xf800) == 0 {
            size += 2;
            pos += 1;
        } else if (word & 0xf800) != 0xd800 {
            size += 3;
            pos += 1;
        } else {
            if pos + 1 > len {
                return 0;
            }
            let diff = word - 0xd800;
            if diff > 0x3ff {
                return 0;
            }
            let next_word = *data.add(pos + 1);
            let diff2 = next_word - 0xdc00;
            if diff2 > 0x3ff {
                return 0;
            }
            size += 4;
            pos += 2;
        }
    }

    size
}

pub fn emit_string(field_offset: i32, assembler: &mut Assembler) {
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
        ; je BYTE >null
        ; mov temp_32, [rdi + 0x10]
        ; test temp, temp
        ; je BYTE >null
        ;;emit_string_copy("\"", assembler)

        ; movsx rsi, DWORD [rdi + 0x10]
        ; lea rdi, [rdi + 0x14]
        ; mov rdx, buffer
        ; mov rcx, QWORD push_string as _
        ; call rcx

        ; add buffer, retval
        ;;emit_string_copy("\"", assembler)
        ; jmp BYTE >exit
        ;null:
        ;;emit_string_copy("\"\"", assembler)
        ;exit:
    );
}

pub fn emit_char(field_offset: i32, assembler: &mut Assembler) {
    json_dynasm!(assembler
        ;;emit_string_copy("\"", assembler)
        ; lea rdi, [object + field_offset]
        ; mov rsi, 1
        ; mov rdx, buffer
        ; mov rcx, QWORD push_string as _
        ; call rcx
        ; add buffer, retval
        ;;emit_string_copy("\"", assembler)
    );
}

pub fn emit_string_size(field_offset: i32, assembler: &mut Assembler) {
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
        ; je BYTE >null
        ; mov temp_32, [rdi + 0x10]
        ; test temp, temp
        ; je BYTE >null

        ; movsx rsi, DWORD [rdi + 0x10]
        ; lea rdi, [rdi + 0x14]
        ; mov temp, QWORD calc_string_size as _
        ; call temp
        ; add buffer, retval

        ;null:
    );
}

pub fn emit_char_length(field_offset: i32, assembler: &mut Assembler) {
    json_dynasm!(assembler
        ; lea rdi, [object + field_offset]
        ; mov rsi, 1
        ; mov temp, QWORD calc_string_size as _
        ; call temp
        ; add buffer, retval
    );
}

#[test]
fn utf16_to_utf8() {
    macro_rules! test_string {
        ($str:expr, $exp:expr) => {
            let val: Vec<u16> = $str.encode_utf16().collect();
            println!("{:?}", val);
            unsafe {
                let expected_length = calc_string_size(val.as_ptr(), val.len());
                let mut dst = [0u8; $exp.len()];
                let length = push_string(val.as_ptr(), val.len(), dst.as_mut_ptr());
                assert_eq!(length, expected_length);
                assert_eq!(String::from_utf8_lossy(&dst[..length]), $exp);
            };
        };
    }
    test_string!("😭", "😭");
    test_string!("\n", "\\n");
    test_string!("\t", "\\t");
    test_string!("\"", "\\\"");
    test_string!("\\", "\\\\");
    test_string!("\u{0}", "\\u0000");
    test_string!("\u{8}", "\\b");
    test_string!("\u{9}", "\\t");
    test_string!("\u{c}", "\\f");
    test_string!("\u{d}", "\\r");
    test_string!(
        "😭\n\t\"\\\u{0}\u{8}\u{9}\u{c}\u{d}",
        "😭\\n\\t\\\"\\\\\\u0000\\b\\t\\f\\r"
    );
}
