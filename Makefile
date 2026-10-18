# 跨平台构建 (Linux / macOS)
# 需要 C++23 (std::format) 以及 LIEF + capstone
#
# 用法:
#   make                      默认 7.1（根 version.json）-> gi-dump
#   make build VERSION=7.0    只编译 -> gi-dump-7.0（不运行）
#   make gen VERSION=7.0      只生成 src/version.hpp
#   make run VERSION=7.0      编译并运行
#   make dump VERSION=7.0     编译 + 运行 + 保存 out/dump70.cs
#   make verify               7.1 基线：运行 + verify.py
#   make versions             列出可用版本
#   make clean

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

# 版本选择：7.1 用根 version.json（保持原基线），其他版本用 version/<ver>/version.json
VERSION ?= 7.1
ifeq ($(VERSION),7.1)
VERSION_JSON := version.json
TARGET       := gi-dump
else
VERSION_JSON := version/$(VERSION)/version.json
TARGET       := gi-dump-$(VERSION)
endif

ifeq ($(filter update,$(MAKECMDGOALS)),)
ifeq ($(wildcard $(VERSION_JSON)),)
$(error version json not found: $(VERSION_JSON))
endif
endif

SRC  := src/main.cpp
HDR  := $(wildcard src/*.hpp)
GEN  := src/version.hpp
DUMP := out/dump$(subst .,,$(VERSION)).cs

.PHONY: all build gen run dump verify versions update clean
all: $(TARGET)
build: $(TARGET)

# 每次构建都按 VERSION 重新生成，避免 make 用旧头文件/根 version.json 覆盖
gen:
	python3 tools/gen_version.py $(VERSION_JSON)

$(TARGET): $(SRC) $(filter-out $(GEN),$(HDR)) gen
	$(CXX) $(CXXFLAGS) -o $@ $(SRC) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET) version/$(VERSION)

dump: $(TARGET)
	./$(TARGET) version/$(VERSION)
	cp out/dump.cs $(DUMP)

verify: $(TARGET)
ifeq ($(VERSION),7.1)
	./$(TARGET) version/$(VERSION)
	python3 verify.py
else
	$(error verify.py is 7.1-only; use: make dump VERSION=$(VERSION))
endif

# 通用换版本：以旧 version.json 为基线，自动生成 version/<ver>/version.json（或 draft）+ 报告。
# 目标没有 version.json 时直接生成；已有则写 version.draft.json（避免覆盖人工成果）。
# 用法: make update VERSION=7.2 [BASE=version.json] [SLOTS=version/7.2/slots.json] [IDA=version/7.2/ida.json]
BASE ?= version.json
SLOTS ?=
IDA ?=
update:
	python3 tools/update.py $(VERSION) --base $(BASE) $(if $(SLOTS),--slots $(SLOTS),) $(if $(IDA),--ida $(IDA),)

versions:
	@echo "7.1  (root version.json)"
	@ls -1 version/*/version.json 2>/dev/null || true

clean:
	rm -f gi-dump gi-dump-*
