This folder contains testfiles for the VSCP & friends suite

test_vesphelper  - test for the tcp/if interface and the libvscphelper library code.
tables-tcp - Tests for tables creating, logging, handling in the tcp/ip interface.

binaryprotocol.cpp, binarytcp.cpp - In-process CTest tests (binaryprotocol) of the binary protocol.
binaryserver.cpp - CTest test (binaryserver) that starts vscpd and tests the binary protocol over TCP.
binary_server/ - Python unittest suite for the binary protocol against a started or running vscpd.
                 Run: python3 binary_server/test_binary_server.py --vscpd <path-to-vscpd>
                 Needs the 'cryptography' and 'pynacl' Python modules.
