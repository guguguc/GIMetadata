# 跨平台构建 (Linux / macOS)
# 需要 C++23 (std::format) 以及 LIEF + capstone
# 用法: make            构建 gi-dump
#       make run ARGS=/path/to/game   运行
#       make clean

CXX      ?= g++
CXXSTD   ?= c++23
OPT      ?= -O2
CXXFLAGS ?= $(OPT) -std=$(CXXSTD) -Wall
LDFLAGS  ?=

PKGS := capstone lief
PKG_CFLAGS := $(shell pkg-config --cflags $(PKGS) 2>/dev/null)
PKG_LIBS   := $(shell pkg-config --libs $(PKGS) 2>/dev/null)
ifeq ($(strip $(PKG_LIBS)),)
PKG_CFLAGS :=
PKG_LIBS   := -lcapstone -lLIEF
endif

CXXFLAGS += -Isrc $(PKG_CFLAGS)
LDFLAGS  += $(PKG_LIBS)

TARGET := gi-dump
SRC    := src/main.cpp
HDR    := $(wildcard src/*.hpp)
GEN    := src/version.hpp

.PHONY: all run clean gen

all: $(TARGET)

# 版本常量：version.json -> src/version.hpp（换版本只改 JSON）
gen: $(GEN)
$(GEN): version.json tools/gen_version.py
	python3 tools/gen_version.py

$(TARGET): $(SRC) $(HDR) $(GEN)
	$(CXX) $(CXXFLAGS) -o $@ $(SRC) $(LDFLAGS)

SAMPLE ?= version/7.1

run: $(TARGET)
	./$(TARGET) $(if $(ARGS),$(ARGS),$(SAMPLE))

clean:
	rm -f $(TARGET)