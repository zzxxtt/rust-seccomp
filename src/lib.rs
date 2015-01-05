#![crate_id = "seccomp"]
#![crate_type = "lib"]
#![allow(non_camel_case_types)] // C definitions

extern crate libc;

use libc::{c_char, c_int, c_uint};
use std::cast::transmute;

#[cfg(target_arch = "x86_64")]
#[path = "syscall64.rs"]
pub mod syscall;

#[cfg(target_arch = "x86")]
#[path = "syscall32.rs"]
pub mod syscall;

enum scmp_filter_ctx {}

static __NR_SCMP_ERROR: c_int = -1;

#[repr(C)]
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
pub enum Op {
    OpNe = 1,
    OpLt = 2,
    OpLe = 3,
    OpEq = 4,
    OpGe = 5,
    OpGt = 6,
}

type scmp_datum_t = u64;

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
        Compare { arg: arg, op: SCMP_CMP_MASKED_EQ, datum_a: mask, datum_b: x }
    }
}

#[link(name = "seccomp")]
extern {
    fn seccomp_init(def_action: u32) -> *mut scmp_filter_ctx;
    fn seccomp_reset(ctx: *mut scmp_filter_ctx, def_action: u32) -> c_int;
    fn seccomp_release(ctx: *mut scmp_filter_ctx);
    fn seccomp_load(ctx: *mut scmp_filter_ctx) -> c_int;
    fn seccomp_rule_add_array(ctx: *mut scmp_filter_ctx, action: u32, syscall: c_int,
                              arg_cnt: c_uint, arg_array: *Compare) -> c_int;
    fn seccomp_syscall_resolve_name(name: *c_char) -> c_int;
}

pub fn syscall_resolve_name(name: &str) -> Option<c_int> {
    unsafe {
        name.with_c_str(|s| {
            let r = seccomp_syscall_resolve_name(s);
            if r == __NR_SCMP_ERROR {
                None
            } else {
                Some(r)
            }
        })
    }
}

/// Default action to take when the ruleset is violated
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
    pub fn new(def_action: Action) -> Filter {
        unsafe {
            let p = seccomp_init(def_action.flag);
            assert!(p.is_not_null());
            Filter{ctx: p}
        }
    }

    pub fn reset(&self, def_action: Action) {
        unsafe {
            assert!(seccomp_reset(self.ctx, def_action.flag) == 0)
        }
    }

    /// Loads the filter into the kernel
    pub fn load(&self) {
        unsafe {
            assert!(seccomp_load(self.ctx) == 0)
        }
    }

    pub fn rule_add(&self, action: Action, syscall: c_int, args: &[Compare]) {
        let len = args.len() as c_uint;
        assert!(len as uint == args.len()); // overflow check
        let ptr = args.as_ptr();
        unsafe {
            assert!(seccomp_rule_add_array(self.ctx, action.flag, syscall, len, ptr) == 0);
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
