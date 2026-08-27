pub type TpmResult = u32;
pub type TpmBool = u8;
pub type TpmModifierIndicator = u32;

pub type TpmlibTpmVersion = core::ffi::c_int;
pub type TpmlibTpmProperty = core::ffi::c_int;
pub type TpmlibInfoFlags = core::ffi::c_int;
pub type TpmlibBlobType = core::ffi::c_int;
pub type TpmlibStateType = core::ffi::c_int;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LibtpmsCallbacks {
    pub size_of_struct: core::ffi::c_int,
    pub tpm_nvram_init: Option<unsafe extern "C" fn() -> TpmResult>,
    pub tpm_nvram_loaddata: Option<
        unsafe extern "C" fn(
            *mut *mut core::ffi::c_uchar,
            *mut u32,
            u32,
            *const core::ffi::c_char,
        ) -> TpmResult,
    >,
    pub tpm_nvram_storedata: Option<
        unsafe extern "C" fn(
            *const core::ffi::c_uchar,
            u32,
            u32,
            *const core::ffi::c_char,
        ) -> TpmResult,
    >,
    pub tpm_nvram_deletename:
        Option<unsafe extern "C" fn(u32, *const core::ffi::c_char, TpmBool) -> TpmResult>,
    pub tpm_io_init: Option<unsafe extern "C" fn() -> TpmResult>,
    pub tpm_io_getlocality:
        Option<unsafe extern "C" fn(*mut TpmModifierIndicator, u32) -> TpmResult>,
    pub tpm_io_getphysicalpresence: Option<unsafe extern "C" fn(*mut TpmBool, u32) -> TpmResult>,
}

impl LibtpmsCallbacks {
    pub const fn empty() -> Self {
        Self {
            size_of_struct: 0,
            tpm_nvram_init: None,
            tpm_nvram_loaddata: None,
            tpm_nvram_storedata: None,
            tpm_nvram_deletename: None,
            tpm_io_init: None,
            tpm_io_getlocality: None,
            tpm_io_getphysicalpresence: None,
        }
    }
}
