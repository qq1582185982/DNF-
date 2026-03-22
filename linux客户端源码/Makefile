.RECIPEPREFIX := >
CXX ?= g++
MUSL_CXX ?= x86_64-linux-musl-g++
CXXFLAGS := -std=c++11 -O2 -Wall -pthread
LDFLAGS :=
STATIC_LDFLAGS := -static -static-libgcc -static-libstdc++
TARGET := dnf-linux-client

SOURCES := \
    main.cpp \
    linux_client_common.cpp \
    linux_config_client.cpp \
    linux_lease_client.cpp \
    linux_tun_manager.cpp \
    linux_packet_tunnel_client.cpp

OBJECTS := $(SOURCES:.cpp=.o)

all: musl

static: $(TARGET)

$(TARGET): $(OBJECTS)
>$(CXX) $(CXXFLAGS) $(OBJECTS) -o $(TARGET) $(STATIC_LDFLAGS)

musl: $(OBJECTS)
>$(MUSL_CXX) $(CXXFLAGS) -static $(OBJECTS) -o $(TARGET)

dynamic: $(OBJECTS)
>$(CXX) $(CXXFLAGS) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

clean:
>rm -f $(OBJECTS) $(TARGET)

.PHONY: all static musl dynamic clean
