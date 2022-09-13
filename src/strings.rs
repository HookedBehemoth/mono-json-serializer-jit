use crate::{json_dynasm, Assembler};

use dynasmrt::*;

/**
 * Pack strings into 64, 32 and 16 bit moves instead of
 * looping over very string.
 */
pub fn emit_string_copy(string: &str, assembler: &mut Assembler) {
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

    if s.len() > 255 {
        json_dynasm!(assembler
            ; add buffer, WORD s.len() as _
        );
    } else {
        json_dynasm!(assembler
            ; add buffer, BYTE s.len() as _
        );
    }
}
