
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

all:	uc udpsrv send_vscp_udp_frame receive_vscp_udp_frame

uc:	udpclient.c
	cc -std=c99 $(CFLAGS) udpclient.c -o uc

udpsrv:     udpsrv.c
	cc -std=c99 udpsrv.c -o udpsrv

crc.o: $(VSCP_SRC_COMMON)/crc.c $(VSCP_SRC_COMMON)/crc.h
	$(CC) $(CFLAGS) -c $(VSCP_SRC_COMMON)/crc.c -o $@

crc8.o: $(VSCP_SRC_COMMON)/crc8.c $(VSCP_SRC_COMMON)/crc8.h
	$(CC) $(CFLAGS) -c $(VSCP_SRC_COMMON)/crc8.c -o $@

aes.o: $(TINY_AES)/aes.c $(TINY_AES)/aes.h
	$(CC) $(CFLAGS) -c $(TINY_AES)/aes.c -o $@			

send_vscp_udp_frame:     send_vscp_udp_frame.o $(OBJ)
	$(CXX)  $(CPPFLAGS) -o $@  send_vscp_udp_frame.o $(OBJ) $(LDFLAGS) -lstdc++ $(EXTRALIBS)

receive_vscp_udp_frame:     receive_vscp_udp_frame.o $(OBJ)
	$(CXX)  $(CPPFLAGS) -o $@ receive_vscp_udp_frame.o  $(OBJ) $(LDFLAGS) $(EXTRALIBS)

clean:
	rm -f uc
	rm -f udpsrv
	rm -f send_vscp_udp_frame
	rm -f receive_vscp_udp_frame
	rm -f *.o
