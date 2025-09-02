#![allow(non_camel_case_types)]
// A lot of this exists in/comes from the `mach2` crate but it remaining on a very old Rust version means that
// all of `libc` is built for types that exist in `core::ffi::*` now.

use core::{
    ffi::{CStr, c_char, c_int, c_uint},
    num::NonZeroI32,
    ptr::NonNull,
};

pub type kern_return_t = c_int;
pub type mach_port_t = c_uint;
pub type natural_t = c_uint;

pub type mach_vm_address_t = u64;
pub type mach_msg_type_name_t = natural_t;
pub type ipc_space_t = mach_port_t;

pub type name_t = *const [c_char; 128];

pub type mach_port_right_t = natural_t;
pub type mach_port_name_t = natural_t;
pub type mach_port_seqno_t = natural_t;
pub type mach_port_context_t = mach_vm_address_t;
pub type mach_msg_bits_t = c_uint;
pub type mach_msg_option_t = c_int;
pub type mach_msg_size_t = natural_t;
pub type mach_msg_id_t = c_int;
pub type mach_msg_timeout_t = natural_t;
pub type mach_msg_trailer_type_t = c_uint;
pub type mach_msg_trailer_size_t = c_uint;

pub const MACH_PORT_NULL: mach_port_t = 0;
pub const MACH_PORT_RIGHT_RECEIVE: mach_port_right_t = 1;
pub const MACH_MSGH_BITS_COMPLEX: mach_msg_bits_t = 0x8000_0000;
pub const MACH_MSG_TYPE_MAKE_SEND: mach_msg_type_name_t = 20;
pub const MACH_MSG_TYPE_COPY_SEND: mach_msg_type_name_t = 19;
pub const MACH_MSG_TYPE_MAKE_SEND_ONCE: mach_msg_type_name_t = 21;
pub const MACH_MSG_TYPE_MOVE_SEND_ONCE: mach_msg_type_name_t = 18;
pub const MACH_SEND_MSG: mach_msg_option_t = 0x0000_0001;
pub const MACH_SEND_TIMEOUT: mach_msg_option_t = 0x0000_0010;
pub const MACH_RCV_MSG: mach_msg_option_t = 0x0000_0002;
pub const MACH_RCV_LARGE: mach_msg_option_t = 0x0000_0004;
pub const MACH_RCV_TIMEOUT: mach_msg_option_t = 0x00000100;
pub const MACH_RCV_TOO_LARGE: kern_return_t = 0x1000_4004;
pub const MACH_RCV_TIMED_OUT: kern_return_t = 0x10004003;
pub const MACH_RCV_TRAILER_AV: mach_msg_trailer_type_t = 7;
pub const MACH_SEND_TIMED_OUT: kern_return_t = 0x1000_0004;

pub const MACH_MSG_TRAILER_FORMAT_0: mach_msg_trailer_type_t = 0;

#[allow(non_snake_case)]
pub fn MACH_MSGH_BITS(remote: mach_msg_bits_t, local: mach_msg_bits_t) -> mach_msg_bits_t {
    remote | (local << 8)
}

// These are ports of the macros from `mach/message.h`, so keep them named the same.
#[allow(non_snake_case)]
pub const fn MACH_RCV_TRAILER_TYPE(msg_type: mach_msg_option_t) -> mach_msg_option_t {
    ((msg_type) & 0xf) << 28
}
#[allow(non_snake_case)]
pub const fn MACH_RCV_TRAILER_ELEMENTS(msg_elems: mach_msg_option_t) -> mach_msg_option_t {
    ((msg_elems) & 0xf) << 24
}

#[repr(C)]
pub struct msg_labels_t {
    sender: mach_port_name_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mach_msg_header_t {
    pub msgh_bits: mach_msg_bits_t,
    pub msgh_size: mach_msg_size_t,
    pub msgh_remote_port: mach_port_t,
    pub msgh_local_port: mach_port_t,
    pub msgh_voucher_port: mach_port_name_t,
    pub msgh_id: mach_msg_id_t,
}

#[expect(missing_docs)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct audit_token_t {
    pub val: [c_uint; 8],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct security_token_t {
    pub val: [c_uint; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mach_msg_trailer_t {
    pub msgh_trailer_type: mach_msg_trailer_type_t,
    pub msgh_trailer_size: mach_msg_trailer_size_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mach_msg_security_trailer_t {
    pub msgh_trailer_type: mach_msg_trailer_type_t,
    pub msgh_trailer_size: mach_msg_trailer_size_t,
    pub msgh_seqno: mach_port_seqno_t,
    pub msgh_sender: security_token_t,
}

pub type mach_msg_format_0_trailer_t = mach_msg_security_trailer_t;
// The size is known at compile-time to fit within `u32`.
#[expect(clippy::as_conversions)]
pub const FORMAT_0_SIZE: u32 = size_of::<mach_msg_format_0_trailer_t>() as u32;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mach_msg_audit_trailer_t {
    pub msgh_trailer_type: mach_msg_trailer_type_t,
    pub msgh_trailer_size: mach_msg_trailer_size_t,
    pub msgh_seqno: mach_port_seqno_t,
    pub msgh_sender: security_token_t,
    pub msgh_audit: audit_token_t,
}

#[repr(C)]
pub struct mach_msg_mac_trailer_t {
    msgh_trailer_type: mach_msg_trailer_type_t,
    msgh_trailer_size: mach_msg_trailer_size_t,
    msgh_seqno: mach_port_seqno_t,
    msgh_sender: security_token_t,
    msgh_audit: audit_token_t,
    msgh_context: mach_port_context_t,
    msgh_ad: i32,
    msgh_labels: msg_labels_t,
}
pub type mach_msg_max_trailer_t = mach_msg_mac_trailer_t;
// Defined in `mach/message.h` as `sizeof mach_msg_max_trailer_t`, which is the same as `mach_msg_mac_trailer_t`.
// The size is known at compile-time to fit within `u32`.
#[expect(clippy::as_conversions)]
pub const MAX_TRAILER_SIZE: u32 = size_of::<mach_msg_max_trailer_t>() as u32;

// The size is known at compile-time to fit within `u32`.
#[expect(clippy::as_conversions)]
pub const AUDIT_TRAILER_SIZE: u32 = size_of::<mach_msg_audit_trailer_t>() as u32;
pub const HEADER_SIZE: usize = size_of::<mach_msg_header_t>();

// mach/notify.h
const MACH_NOTIFY_FIRST: c_int = 0o100;
// Receive right has no extant send rights */
pub const MACH_NOTIFY_SEND_ONCE: c_int = MACH_NOTIFY_FIRST + 0o7;

pub type MachPortReleaser = unsafe extern "C" fn(ipc_space_t, mach_port_t) -> KernReturn;

pub struct MachPort {
    pub inner: mach_port_t,
    pub release: MachPortReleaser,
}

impl Drop for MachPort {
    fn drop(&mut self) {
        // SAFETY: It is valid to release an active port or `MACH_DEAD_PORT`.
        let _ = unsafe { (self.release)(mach_task_self(), self.inner) };
    }
}

/// A failure that occured during a mach port operation.
#[derive(Clone, Copy, PartialEq)]
#[repr(transparent)]
pub struct KernError(NonZeroI32);

impl KernError {
    pub(crate) fn code(self) -> kern_return_t {
        self.0.get()
    }
}

impl std::fmt::Debug for KernError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match mach_error_string(*self) {
            // SAFETY: The C string is a valid, non-null constant pointer returned by the OS.
            Some(val) => unsafe { CStr::from_ptr(val.as_ptr()).to_string_lossy() },
            None => std::borrow::Cow::Borrowed("unknown"),
        };

        f.debug_struct("KernError")
            .field("code", &self.0)
            .field("description", &description.as_ref())
            .finish()
    }
}

impl std::fmt::Display for KernError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{self:?}"))
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub(crate) struct BootstrapError(pub KernError);

impl BootstrapError {
    pub(crate) fn description(self) -> String {
        // SAFETY: The C string is a valid pointer returned by the OS.
        let err_msg = unsafe { CStr::from_ptr(bootstrap_strerror(self)) };
        err_msg.to_str().map(String::from).unwrap()
    }
}

// XXX: Our MSRV is >= 1.80, which means these are unconditionally FFI safe.
pub type BootstrapReturn = Result<(), BootstrapError>;
pub type KernReturn = Result<(), KernError>;

unsafe extern "C" {
    pub safe static bootstrap_port: mach_port_t;

    // Ever since macOS 10.6 its been possible to call `bootstrap_check_in` to both register and advertise a mach service with `launchd`,
    // which is well above our supported version. Its also not deprecated like some other registration functions.
    pub fn bootstrap_check_in(
        bp: mach_port_t,
        service_name: name_t,
        sp: *mut mach_port_t,
    ) -> BootstrapReturn;
    pub fn bootstrap_look_up(
        bp: mach_port_t,
        service_name: name_t,
        sp: *mut mach_port_t,
    ) -> BootstrapReturn;
    pub safe fn bootstrap_strerror(r: BootstrapError) -> *const c_char;

    safe fn mach_error_string(error_value: KernError) -> Option<NonNull<c_char>>;
    pub safe fn mach_task_self() -> mach_port_t;

    pub fn mach_msg_destroy(msg: *const mach_msg_header_t);
    pub fn mach_port_allocate(
        task: ipc_space_t,
        right: mach_port_right_t,
        name: *mut mach_port_name_t,
    ) -> KernReturn;
    pub fn mach_port_deallocate(task: ipc_space_t, name: mach_port_t) -> KernReturn;
    // NB: This is deprecated as of macOS 12 due to being an "Inherently unsafe API" but we need to support older versions then that because
    // Rust support 10.12+.
    pub fn mach_port_destroy(task: ipc_space_t, name: mach_port_t) -> KernReturn;
    pub fn mach_port_insert_right(
        task: ipc_space_t,
        name: mach_port_name_t,
        poly: mach_port_t,
        polyPoly: mach_msg_type_name_t,
    ) -> KernReturn;
    pub fn mach_msg(
        msg: *mut mach_msg_header_t,
        option: mach_msg_option_t,
        send_size: mach_msg_size_t,
        recv_size: mach_msg_size_t,
        recv_name: mach_port_name_t,
        timeout: mach_msg_timeout_t,
        notify: mach_port_name_t,
    ) -> KernReturn;
}
