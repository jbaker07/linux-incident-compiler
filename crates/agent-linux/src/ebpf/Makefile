UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  TARGET_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
  TARGET_ARCH := arm64
else ifeq ($(UNAME_M),arm64)
  TARGET_ARCH := arm64
else
  $(error Unsupported arch $(UNAME_M))
endif

CLANG ?= clang

BPF_SRCS := $(wildcard *.bpf.c)
BPF_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)

# BPF compile flags: kernel-only headers
CFLAGS := -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_$(TARGET_ARCH)
INCLUDES := -I. -I/usr/include/bpf
# hard drop any generic user includes from BPF path
CFLAGS := $(filter-out -I/usr/include,$(CFLAGS))

all: $(BPF_OBJS)

%.bpf.o: %.bpf.c
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f *.bpf.o
