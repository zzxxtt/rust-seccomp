#!/usr/bin/env python3

import sys

if len(sys.argv) != 2:
    sys.stderr.write("usage: %s path_to_header\n" % sys.argv[0])
    sys.exit(1)

print("extern crate libc;")
print("use libc::c_int;")

with open(sys.argv[1]) as f:
    for line in f:
        if line.startswith("#define __NR_"):
            name, number = line.strip().replace("#define __NR_", "").split(" ")
            print("pub static {}: c_int = {};".format(name.upper(), number))
