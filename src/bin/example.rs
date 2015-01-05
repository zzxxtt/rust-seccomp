extern crate libc;
extern crate seccomp;

use seccomp::{Filter, Compare, ACT_KILL, ACT_ALLOW, OpEq, syscall};

#[start]
fn start(_argc: int, _argv: **u8) -> int {
    use libc::{c_void, size_t};

    let outstr = bytes!("output for stdout\n");
    let errstr = bytes!("output for stderr\n");

    // set killing the process as the default handler, as we want a whitelist
    let filter = Filter::new(ACT_KILL);

    // allow `write(1, outstr.as_ptr(), outstr.len())`
    filter.rule_add(ACT_ALLOW, syscall::WRITE, [
        Compare::new(0, OpEq, 1),
        Compare::new(1, OpEq, outstr.as_ptr() as u64),
        Compare::new(2, OpEq, outstr.len() as u64)
    ]);

    // allow `write(2, errstr.as_ptr(), errstr.len())`
    filter.rule_add(ACT_ALLOW, syscall::WRITE, [
        Compare::new(0, OpEq, 2),
        Compare::new(1, OpEq, errstr.as_ptr() as u64),
        Compare::new(2, OpEq, errstr.len() as u64)
    ]);

    // allow `exit_group(0)`
    filter.rule_add(ACT_ALLOW, syscall::EXIT_GROUP, [Compare::new(0, OpEq, 0)]);

    // activate the filtering rules
    filter.load();

    unsafe {
        libc::write(1, outstr.as_ptr() as *c_void, outstr.len() as size_t);
        libc::write(2, errstr.as_ptr() as *c_void, errstr.len() as size_t);
        libc::exit(0)
    }
}
