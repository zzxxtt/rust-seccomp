use std::libc::{c_int, c_uint};

enum scmp_filter_ctx {}

#[link_args = "-lseccomp"]
extern {
    fn seccomp_init(def_action: u32) -> *mut scmp_filter_ctx;
    fn seccomp_reset(ctx: *mut scmp_filter_ctx, def_action: u32) -> c_int;
    fn seccomp_release(ctx: *mut scmp_filter_ctx);
    fn seccomp_load(ctx: *mut scmp_filter_ctx) -> c_int;
    fn seccomp_rule_add(ctx: *mut scmp_filter_ctx, action: u32, syscall: c_int,
                        zero: c_uint) -> c_int;
}

/// Default action to take when the ruleset is violated
struct Action {
    priv flag: u32
}

/// Kill the process
static ACT_KILL: Action = Action{flag: 0x00000000};

/// Throw a SIGSYS signal
static ACT_TRAP: Action = Action{flag: 0x00030000};

/// Allow the system call to be executed
static ACT_ALLOW: Action = Action{flag: 0x7fff0000};

/// Notify a tracing process with the specified value
fn act_trace(msg_num: u16) -> Action {
    Action{flag: 0x7ff00000 | (msg_num as u32 & 0x0000ffff)}
}

/// Return the specified error code
fn act_errno(errno: u16) -> Action {
    Action{flag: 0x00050000 | (errno as u32 & 0x0000ffff) }
}

struct Filter {
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

    pub fn rule_add(&self, action: Action, syscall: c_int) {
        unsafe {
            assert!(seccomp_rule_add(self.ctx, action.flag, syscall, 0) == 0);
        }
    }
}

impl Drop for Filter {
    fn finalize(&self) {
        unsafe {
            seccomp_release(self.ctx)
        }
    }
}

fn main() {
    let filter = Filter::new(ACT_TRAP);
    filter.rule_add(ACT_ALLOW, 0); // read
    filter.rule_add(ACT_ALLOW, 2); // open
    filter.rule_add(ACT_ALLOW, 3); // close
    filter.rule_add(ACT_ALLOW, 11); // munmap
    filter.rule_add(ACT_ALLOW, 28); // madvise
    filter.rule_add(ACT_ALLOW, 60); // exit
    filter.rule_add(ACT_ALLOW, 202); // futex
    filter.load();
}
