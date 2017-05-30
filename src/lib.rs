
#![allow(non_camel_case_types)] // C definitions

extern crate libc;

use libc::{c_char, c_int, c_uint};
use std::mem::transmute;
use std::ffi::CString;
pub use syscall::Syscall;

#[cfg(target_arch = "x86_64")]
#[path = "syscall64.rs"]
pub mod syscall;

#[cfg(target_arch = "x86")]
#[path = "syscall32.rs"]
pub mod syscall;

enum scmp_filter_ctx {}

static __NR_SCMP_ERROR: c_int = -1;

#[repr(C)]
#[derive(Copy,Clone)]
pub enum scmp_compare {
    _SCMP_CMP_MIN = 0,
    SCMP_CMP_NE = 1,
    SCMP_CMP_LT = 2,
    SCMP_CMP_LE = 3,
    SCMP_CMP_EQ = 4,
    SCMP_CMP_GE = 5,
    SCMP_CMP_GT = 6,
    SCMP_CMP_MASKED_EQ = 7,
    _SCMP_CMP_MAX,
}

#[repr(C)]
#[derive(Copy,Clone)]
pub enum Op {
    OpNe = 1,
    OpLt = 2,
    OpLe = 3,
    OpEq = 4,
    OpGe = 5,
    OpGt = 6,
}

type scmp_datum_t = u64;

#[derive(Copy,Clone)]
#[repr(C)]
pub struct Compare {
    arg: c_uint,
    op: scmp_compare,
    datum_a: scmp_datum_t,
    datum_b: scmp_datum_t
}

impl Compare {
    pub fn new(arg: c_uint, op: Op, x: u64) -> Compare {
        Compare { arg: arg, op: unsafe { transmute(op) }, datum_a: x, datum_b: 0 }
    }

    pub fn new_masked_eq(arg: c_uint, mask: u64, x: u64) -> Compare {
        Compare { arg: arg, op: scmp_compare::SCMP_CMP_MASKED_EQ, datum_a: mask, datum_b: x }
    }
}

#[link(name = "seccomp")]
extern "C" {
    fn seccomp_init(def_action: u32) -> *mut scmp_filter_ctx;
    fn seccomp_reset(ctx: *mut scmp_filter_ctx, def_action: u32) -> c_int;
    fn seccomp_release(ctx: *mut scmp_filter_ctx);
    fn seccomp_load(ctx: *mut scmp_filter_ctx) -> c_int;
    fn seccomp_rule_add_array(ctx: *mut scmp_filter_ctx, action: u32, syscall: u32,
                              arg_cnt: c_uint, arg_array: *const Compare) -> c_int;
    fn seccomp_syscall_resolve_name(name: *const c_char) -> c_int;
}

pub fn syscall_resolve_name(name: &str) -> Option<c_int> {
    unsafe {
        let buf = CString::new(name.as_bytes()).unwrap();
        let r = seccomp_syscall_resolve_name(buf.as_ptr());
        if r == __NR_SCMP_ERROR {
            None
        } else {
            Some(r)
        }
    }
}

/// Default action to take when the ruleset is violated
#[derive(Copy,Clone)]
pub struct Action {
    flag: u32
}

/// Kill the process
pub static ACT_KILL: Action = Action{flag: 0x00000000};

/// Throw a SIGSYS signal
pub static ACT_TRAP: Action = Action{flag: 0x00030000};

/// Allow the system call to be executed
pub static ACT_ALLOW: Action = Action{flag: 0x7fff0000};

/// Notify a tracing process with the specified value
pub fn act_trace(msg_num: u16) -> Action {
    Action{flag: 0x7ff00000 | (msg_num as u32 & 0x0000ffff)}
}

/// Return the specified error code
pub fn act_errno(errno: u16) -> Action {
    Action{flag: 0x00050000 | (errno as u32 & 0x0000ffff) }
}

pub struct Filter {
    ctx: *mut scmp_filter_ctx
}

impl Filter {
    pub fn new(def_action: &Action) -> Result<Filter, usize> {
        let p;
        unsafe {
            p = seccomp_init(def_action.flag);
        }
        if p.is_null() {
            Result::Err(1)
        } else {
            Result::Ok(Filter{ctx: p})
        }
    }

    pub fn reset(&self, def_action: Action) -> Result<(), usize> {
        let r;
        unsafe {
            r = seccomp_reset(self.ctx, def_action.flag);
        }
        if r == 0 {
            Result::Ok(())
        } else {
            Result::Err(1)
        }
    }

    /// Loads the filter into the kernel
    pub fn load(&self) -> Result<(), usize> {
        let r;
        unsafe {
            r = seccomp_load(self.ctx);
        }
        if r == 0 {
            Result::Ok(())
        } else {
            Result::Err(1)
        }
    }

    pub fn rule_add(&self, action: &Action, syscall: Syscall, args: &[Compare]) -> Result<(), usize> {
        let len = args.len() as usize;
        assert!(len == args.len()); // overflow check
        let ptr = args.as_ptr();
        let r;
        unsafe {
            r = seccomp_rule_add_array(self.ctx, action.flag, syscall as u32, len as u32, ptr)
        }
        if r == 0 {
            Result::Ok(())
        } else {
            Result::Err(1)
        }
    }
}

impl Drop for Filter {
    fn drop(&mut self) {
        unsafe {
            seccomp_release(self.ctx)
        }
    }
}
