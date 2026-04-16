
# This test requires the vscphelper library (libvscphelper.so) to be installed
# or built separately from https://github.com/grodansparadis/vscp-helper-lib
VSCP_COMMON = ../../third-party/vscp/src/vscp/common

all:	test_tables_tcp


test_tables_tcp:       test_tables_tcp.c
	cc -std=c99 test_tables_tcp.c -o test_tables_tcp -I$(VSCP_COMMON) -lm -lvscphelper

clean:
	rm -f test_helperlib
	rm -f *.o
