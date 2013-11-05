#[allow(cstack)];

use std::libc::{c_char, c_int, c_uint};

enum scmp_filter_ctx {}

#[repr(C)]
enum scmp_compare {
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

type scmp_datum_t = u64;

struct scmp_arg_cmp {
    arg: c_uint,
    op: scmp_compare,
    datum_a: scmp_datum_t,
    datum_b: scmp_datum_t
}

#[link_args = "-lseccomp"]
extern {
    fn seccomp_init(def_action: u32) -> *mut scmp_filter_ctx;
    fn seccomp_reset(ctx: *mut scmp_filter_ctx, def_action: u32) -> c_int;
    fn seccomp_release(ctx: *mut scmp_filter_ctx);
    fn seccomp_load(ctx: *mut scmp_filter_ctx) -> c_int;
    fn seccomp_rule_add_array(ctx: *mut scmp_filter_ctx, action: u32, syscall: c_int,
                              arg_cnt: c_uint, arg_array: *scmp_arg_cmp) -> c_int;
    fn seccomp_syscall_resolve_name(name: *c_char) -> c_int;
}

pub fn syscall_resolve_name(name: &str) -> c_int {
    unsafe {
        do name.with_c_str |s| {
            seccomp_syscall_resolve_name(s)
        }
    }
}

/// Default action to take when the ruleset is violated
pub struct Action {
    priv flag: u32
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
    priv ctx: *mut scmp_filter_ctx
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

    pub fn rule_add(&self, action: Action, syscall: c_int, args: &[scmp_arg_cmp]) {
        let len = args.len() as c_uint;
        assert!(len as uint == args.len()); // overflow check
        let ptr = std::vec::raw::to_ptr(args);
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

#[start]
fn start(_argc: int, _argv: **u8) -> int {
    use std::libc::{c_void, size_t};

    let filter = Filter::new(ACT_TRAP);
    let stdout = scmp_arg_cmp { arg: 0, op: SCMP_CMP_EQ, datum_a: 1, datum_b: 0 };
    filter.rule_add(ACT_ALLOW, 1, [stdout]); // write(1, x)
    filter.rule_add(ACT_ALLOW, 231, []); // exit_group(x)
    filter.load();

    let s = bytes!("foobar\n");
    unsafe { std::libc::write(1, std::vec::raw::to_ptr(s) as *c_void, s.len() as size_t); }

    0
}
