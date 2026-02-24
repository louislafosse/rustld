#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolVisibility {
    Default = 0,
    Internal = 1,
    Hidden = 2,
    Protected = 3,
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct SymbolOtherField(u8);

impl SymbolOtherField {
    #[inline(always)]
    pub fn symbol_visibility(self) -> SymbolVisibility {
        // mask restricts to 0..=3 which matches the enum repr
        unsafe { core::mem::transmute(self.0 & 3) }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Symbol {
    /// String table index of the symbol name.
    pub st_name: u32,
    #[cfg(target_pointer_width = "32")]
    pub st_value: usize,
    #[cfg(target_pointer_width = "32")]
    pub st_size: usize,
    pub st_info: u8,
    pub st_other: SymbolOtherField,
    pub st_shndx: u16,
    #[cfg(target_pointer_width = "64")]
    pub st_value: usize,
    #[cfg(target_pointer_width = "64")]
    pub st_size: usize,
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct SymbolTable(*const Symbol);

impl SymbolTable {
    #[inline(always)]
    pub const fn new(ptr: *const Symbol) -> Self {
        Self(ptr)
    }

    #[inline(always)]
    pub unsafe fn get_ref(&self, index: usize) -> &'static Symbol {
        &*self.0.add(index)
    }

    #[inline(always)]
    pub const fn as_ptr(&self) -> *const Symbol {
        self.0
    }

    #[inline(always)]
    pub const fn into_inner(self) -> *const Symbol {
        self.0
    }
}
