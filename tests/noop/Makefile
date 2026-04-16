

VSCP_COMMON    = ../../third-party/vscp/src/vscp/common
VSCP_SRC_COMMON = ../../third-party/vscp/src/common
MONGOOSE       = ../../third-party/vscp/third_party/mongoose
TINY_AES       = ../../third-party/vscp/third_party/tiny-aes

CC = gcc
CXX = g++
MONGOOSE_CFLAGS = -DMG_ENABLE_THREADS -DMG_ENABLE_GETADDRINFO -UMG_ENABLE_SSL
CFLAGS = -g -O0 -pthread -D MG_ENABLE_THREADS \
	-I$(VSCP_COMMON) \
	-I$(VSCP_SRC_COMMON) \
	-I$(MONGOOSE) \
	-I$(TINY_AES)
CXXFLAGS = -g -O0
CPPFLAGS = \
	-I$(VSCP_COMMON) \
	-I$(VSCP_SRC_COMMON) \
	-I$(MONGOOSE) \
	-I$(TINY_AES)
CPPFLAGS += `wx-config --cxxflags base `
CPPFLAGS += $(MONGOOSE_CFLAGS)
LDFLAGS =
EXTRALIBS =  -lz -lrt -lm -lcrypto -lpthread
EXTRALIBS += `wx-config --libs base`
TEST_OBJECTS =  noop.o \

TEST_SPECIALS = vscphelper.o \
	vscpremotetcpif.o \
	guid.o \
	mongoose.o \
	crc8.o \
	crc.o \
	aes.o



all:	noop

vscphelper.o: $(VSCP_COMMON)/vscphelper.cpp $(VSCP_COMMON)/vscphelper.h
	$(CXX)  $(CXXFLAGS) $(CPPFLAGS) -c $(VSCP_COMMON)/vscphelper.cpp -o $@

vscpremotetcpif.o: $(VSCP_COMMON)/vscpremotetcpif.cpp $(VSCP_COMMON)/vscpremotetcpif.h
	$(CXX)  $(CXXFLAGS) $(CPPFLAGS) -c $(VSCP_COMMON)/vscpremotetcpif.cpp -o $@

guid.o: $(VSCP_COMMON)/guid.cpp $(VSCP_COMMON)/guid.h
	$(CXX)  $(CXXFLAGS) $(CPPFLAGS) -c $(VSCP_COMMON)/guid.cpp -o $@

crc.o: $(VSCP_SRC_COMMON)/crc.c $(VSCP_SRC_COMMON)/crc.h
	$(CC) $(CFLAGS) -c $(VSCP_SRC_COMMON)/crc.c -o $@

crc8.o: $(VSCP_SRC_COMMON)/crc8.c $(VSCP_SRC_COMMON)/crc8.h
	$(CC) $(CFLAGS) -c $(VSCP_SRC_COMMON)/crc8.c -o $@

aes.o: $(TINY_AES)/aes.c $(TINY_AES)/aes.h
	$(CC) $(CFLAGS) -c $(TINY_AES)/aes.c -o $@

mongoose.o: $(MONGOOSE)/mongoose.c $(MONGOOSE)/mongoose.h
	$(CC) $(CFLAGS) $(MONGOOSE_CFLAGS) -c $(MONGOOSE)/mongoose.c -o $@

noop: $(TEST_OBJECTS) $(TEST_SPECIALS)
	$(CXX)  -o $@ $(TEST_OBJECTS) $(TEST_SPECIALS) $(LDFLAGS) $(EXTRALIBS)

clean:
	rm -f noop
	rm -f *.o
