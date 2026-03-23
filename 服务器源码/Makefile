CXX ?= g++
MUSL_CXX ?= x86_64-linux-musl-g++
CXXFLAGS = -std=c++11 -O2 -Wall -pthread
TARGET = dnf-tunnel-server
SOURCES = tcp_tunnel_server.cpp tcp_config_server.cpp ip_pool_manager.cpp tun_manager.cpp peer_coord.cpp
HEADERS = tcp_config_server.h ip_pool_manager.h ip_lease_protocol.h packet_tunnel_protocol.h tun_manager.h peer_coord.h

all: musl

$(TARGET): $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $@
	@echo "build done: $(TARGET)"
	@echo "run: ./$(TARGET)"

static: $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) -static $(SOURCES) -o $(TARGET)
	@echo "static build done: $(TARGET)"
	@ls -lh $(TARGET)

musl: $(SOURCES) $(HEADERS)
	$(MUSL_CXX) $(CXXFLAGS) -static $(SOURCES) -o $(TARGET)
	@echo "musl static build done: $(TARGET)"
	@ls -lh $(TARGET)

clean:
	rm -f $(TARGET) dnf-tunnel-server-asan dnf-tunnel-server-g
	@echo "clean done"

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "installed: /usr/local/bin/$(TARGET)"

uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "uninstalled: /usr/local/bin/$(TARGET)"

.PHONY: all static musl clean install uninstall
