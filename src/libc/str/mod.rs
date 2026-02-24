pub(crate) unsafe fn strlen(start_character: *const u8) -> usize {
    let mut len = 0usize;
    while *start_character.add(len) != 0 {
        len += 1;
    }
    len
}
