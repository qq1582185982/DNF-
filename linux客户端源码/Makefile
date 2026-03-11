.RECIPEPREFIX := >
CXX := g++
CXXFLAGS := -std=c++11 -O2 -Wall -pthread
TARGET := dnf-linux-client

SOURCES := \
    main.cpp \
    linux_client_common.cpp \
    linux_config_client.cpp \
    linux_lease_client.cpp \
    linux_tun_manager.cpp \
    linux_packet_tunnel_client.cpp

OBJECTS := $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
>$(CXX) $(CXXFLAGS) $(OBJECTS) -o $(TARGET)

clean:
>rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean