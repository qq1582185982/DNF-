# DNF 隧道服务器 Makefile

CXX = g++
CXXFLAGS = -std=c++11 -O2 -Wall -pthread
TARGET = dnf-tunnel-server
SOURCES = tcp_tunnel_server.cpp tcp_config_server.cpp
HEADERS = tcp_config_server.h

# 默认目标：动态编译
all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $@
	@echo "编译完成: $(TARGET)"
	@echo "运行: ./$(TARGET)"

# 静态编译（兼容性最好）
static: $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) -static $(SOURCES) -o $(TARGET)
	@echo "静态编译完成: $(TARGET)"
	@echo "文件大小:"
	@ls -lh $(TARGET)

# 清理
clean:
	rm -f $(TARGET)
	@echo "清理完成"

# 安装
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "已安装到: /usr/local/bin/$(TARGET)"

# 卸载
uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "已卸载"

.PHONY: all static clean install uninstall
