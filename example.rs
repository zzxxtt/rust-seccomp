extern crate seccomp;

use seccomp::{Filter, Compare, ACT_TRAP, ACT_ALLOW, OpEq, syscall};

#[start]
fn start(_argc: int, _argv: **u8) -> int {
    use std::libc::{c_void, size_t};

    let filter = Filter::new(ACT_TRAP);

    // write(1, x, y)
    let stdout = Compare::new(0, OpEq, 1);
    filter.rule_add(ACT_ALLOW, syscall::WRITE, [stdout]);

    // exit_group(x)
    filter.rule_add(ACT_ALLOW, syscall::EXIT_GROUP, []);

    filter.load();

    let s = bytes!("foobar\n");
    unsafe { std::libc::write(1, s.as_ptr() as *c_void, s.len() as size_t); }
    unsafe { std::libc::exit(0) }
}
