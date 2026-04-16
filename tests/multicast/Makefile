
VSCP_COMMON    = ../../third-party/vscp/src/vscp/common
VSCP_SRC_COMMON = ../../third-party/vscp/src/common
TINY_AES       = ../../third-party/vscp/third_party/tiny-aes

CC = gcc
CXX = g++
CFLAGS = -std=c99 -g -O0 -D_BSD_SOURCE \
	-I$(VSCP_COMMON) \
	-I$(VSCP_SRC_COMMON) \
	-I$(TINY_AES)
CXXFLAGS = -g -O0
CPPFLAGS = \
	-I$(VSCP_COMMON) \
	-I$(VSCP_SRC_COMMON) \
	-I$(TINY_AES)
LDFLAGS =
EXTRALIBS =  -lz
OBJ = crc.o crc8.o aes.o

all: sender alistener mclistener mcsender

crc.o: $(VSCP_SRC_COMMON)/crc.c $(VSCP_SRC_COMMON)/crc.h
	$(CC) $(CFLAGS) -c $(VSCP_SRC_COMMON)/crc.c -o $@

crc8.o: $(VSCP_SRC_COMMON)/crc8.c $(VSCP_SRC_COMMON)/crc8.h
	$(CC) $(CFLAGS) -c $(VSCP_SRC_COMMON)/crc8.c -o $@

aes.o: $(TINY_AES)/aes.c $(TINY_AES)/aes.h
	$(CC) $(CFLAGS) -c $(TINY_AES)/aes.c -o $@

sender: $(OBJ) sender.c
	$(CC) $(CFLAGS) sender.c -o $@ $(OBJ)

alistener:	$(OBJ) alistener.c
	$(CC) $(CFLAGS) alistener.c -o $@ $(OBJ)

mclistener:	$(OBJ) mclistener.c
	$(CC) $(CFLAGS) mclistener.c -o $@ $(OBJ)

mcsender: $(OBJ) mcsender.c
	$(CC) $(CFLAGS) mcsender.c -o $@ $(OBJ)

clean:
	rm -f alistener
	rm -f mclistener
	rm -f sender
	rm -f *.o

$(ALWAYS_BUILD):  .FORCE

.FORCE:

# Include dependency info, if present:
-include .deps/*.d

.PHONY: all install uninstall clean distclean data .FORCE
