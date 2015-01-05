#!/usr/bin/env python3

import sys

if len(sys.argv) != 2:
    sys.stderr.write("usage: %s path_to_header\n" % sys.argv[0])
    sys.exit(1)

print("#[derive(Show, FromPrimitive, Copy)]")
print("pub enum Syscall {")
with open(sys.argv[1]) as f:
    for line in f:
        if line.startswith("#define __NR_"):
            name, number = line.strip().replace("#define __NR_", "").split(" ")
            print("  {} = {},".format(name.upper(), number))
print("}")
