savedcmd_lkm.o := gcc -Wp,-MMD,./.lkm.o.d -nostdinc -I/home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include -I/home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated -I/home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include -I/home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include -I/home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/uapi -I/home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/uapi -I/home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi -I/home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/generated/uapi -include /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/compiler-version.h -include /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kconfig.h -include /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/compiler_types.h -D__KERNEL__ -mlittle-endian -DKASAN_SHADOW_SCALE_SHIFT= -std=gnu11 -fshort-wchar -funsigned-char -fno-common -fno-PIE -fno-strict-aliasing -mgeneral-regs-only -DCONFIG_CC_HAS_K_CONSTRAINT=1 -Wno-psabi -mabi=lp64 -fno-asynchronous-unwind-tables -fno-unwind-tables -mbranch-protection=pac-ret -Wa,-march=armv8.5-a -DARM64_ASM_ARCH='"armv8.5-a"' -DKASAN_SHADOW_SCALE_SHIFT= -fno-delete-null-pointer-checks -O2 -fno-allow-store-data-races -fstack-protector-strong -fno-omit-frame-pointer -fno-optimize-sibling-calls -ftrivial-auto-var-init=zero -fno-stack-clash-protection -fmin-function-alignment=4 -fstrict-flex-arrays=3 -fno-strict-overflow -fno-stack-check -fconserve-stack -fno-builtin-wcslen -Wall -Wundef -Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Werror=strict-prototypes -Wno-format-security -Wno-trigraphs -Wno-frame-address -Wno-address-of-packed-member -Wmissing-declarations -Wmissing-prototypes -Wframe-larger-than=2048 -Wno-main -Wno-dangling-pointer -Wvla -Wno-pointer-sign -Wcast-function-type -Wno-stringop-overflow -Wno-array-bounds -Wno-alloc-size-larger-than -Wimplicit-fallthrough=5 -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -Wenum-conversion -fzero-init-padding-bits=all -Wextra -Wunused -Wno-unused-but-set-variable -Wno-unused-const-variable -Wno-packed-not-aligned -Wno-format-overflow -Wno-format-truncation -Wno-stringop-truncation -Wno-override-init -Wno-missing-field-initializers -Wno-type-limits -Wno-shift-negative-value -Wno-maybe-uninitialized -Wno-sign-compare -Wno-unused-parameter -g -fno-var-tracking -femit-struct-debug-baseonly -mstack-protector-guard=sysreg -mstack-protector-guard-reg=sp_el0 -mstack-protector-guard-offset=1240  -DMODULE  -DKBUILD_BASENAME='"lkm"' -DKBUILD_MODNAME='"lkm"' -D__KBUILD_MODNAME=kmod_lkm -c -o lkm.o lkm.c  

source_lkm.o := lkm.c

deps_lkm.o := \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/compiler-version.h \
    $(wildcard include/config/CC_VERSION_TEXT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kconfig.h \
    $(wildcard include/config/CPU_BIG_ENDIAN) \
    $(wildcard include/config/BOOGER) \
    $(wildcard include/config/FOO) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/compiler_types.h \
    $(wildcard include/config/DEBUG_INFO_BTF) \
    $(wildcard include/config/PAHOLE_HAS_BTF_TAG) \
    $(wildcard include/config/FUNCTION_ALIGNMENT) \
    $(wildcard include/config/CC_HAS_SANE_FUNCTION_ALIGNMENT) \
    $(wildcard include/config/X86_64) \
    $(wildcard include/config/ARM64) \
    $(wildcard include/config/LD_DEAD_CODE_DATA_ELIMINATION) \
    $(wildcard include/config/LTO_CLANG) \
    $(wildcard include/config/HAVE_ARCH_COMPILER_H) \
    $(wildcard include/config/CC_HAS_COUNTED_BY) \
    $(wildcard include/config/UBSAN_SIGNED_WRAP) \
    $(wildcard include/config/CC_HAS_ASM_INLINE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/compiler_attributes.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/compiler-gcc.h \
    $(wildcard include/config/MITIGATION_RETPOLINE) \
    $(wildcard include/config/ARCH_USE_BUILTIN_BSWAP) \
    $(wildcard include/config/SHADOW_CALL_STACK) \
    $(wildcard include/config/KCOV) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/compiler.h \
    $(wildcard include/config/ARM64_PTR_AUTH_KERNEL) \
    $(wildcard include/config/ARM64_PTR_AUTH) \
    $(wildcard include/config/BUILTIN_RETURN_ADDRESS_STRIPS_PAC) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/module.h \
    $(wildcard include/config/MODULES) \
    $(wildcard include/config/SYSFS) \
    $(wildcard include/config/MODULES_TREE_LOOKUP) \
    $(wildcard include/config/LIVEPATCH) \
    $(wildcard include/config/STACKTRACE_BUILD_ID) \
    $(wildcard include/config/ARCH_USES_CFI_TRAPS) \
    $(wildcard include/config/MODULE_SIG) \
    $(wildcard include/config/GENERIC_BUG) \
    $(wildcard include/config/KALLSYMS) \
    $(wildcard include/config/SMP) \
    $(wildcard include/config/TRACEPOINTS) \
    $(wildcard include/config/TREE_SRCU) \
    $(wildcard include/config/BPF_EVENTS) \
    $(wildcard include/config/DEBUG_INFO_BTF_MODULES) \
    $(wildcard include/config/JUMP_LABEL) \
    $(wildcard include/config/TRACING) \
    $(wildcard include/config/EVENT_TRACING) \
    $(wildcard include/config/FTRACE_MCOUNT_RECORD) \
    $(wildcard include/config/KPROBES) \
    $(wildcard include/config/HAVE_STATIC_CALL_INLINE) \
    $(wildcard include/config/KUNIT) \
    $(wildcard include/config/PRINTK_INDEX) \
    $(wildcard include/config/MODULE_UNLOAD) \
    $(wildcard include/config/MITIGATION_ITS) \
    $(wildcard include/config/CONSTRUCTORS) \
    $(wildcard include/config/FUNCTION_ERROR_INJECTION) \
    $(wildcard include/config/DYNAMIC_DEBUG_CORE) \
    $(wildcard include/config/ARCH_HAS_EXECMEM_ROX) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/list.h \
    $(wildcard include/config/LIST_HARDENED) \
    $(wildcard include/config/DEBUG_LIST) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/container_of.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/build_bug.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/compiler.h \
    $(wildcard include/config/TRACE_BRANCH_PROFILING) \
    $(wildcard include/config/PROFILE_ALL_BRANCHES) \
    $(wildcard include/config/OBJTOOL) \
    $(wildcard include/config/64BIT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/rwonce.h \
    $(wildcard include/config/LTO) \
    $(wildcard include/config/AS_HAS_LDAPR) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/rwonce.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kasan-checks.h \
    $(wildcard include/config/KASAN_GENERIC) \
    $(wildcard include/config/KASAN_SW_TAGS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/types.h \
    $(wildcard include/config/HAVE_UID16) \
    $(wildcard include/config/UID16) \
    $(wildcard include/config/ARCH_DMA_ADDR_T_64BIT) \
    $(wildcard include/config/PHYS_ADDR_T_64BIT) \
    $(wildcard include/config/ARCH_32BIT_USTAT_F_TINODE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/uapi/asm/types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/int-ll64.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/int-ll64.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/uapi/asm/bitsperlong.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitsperlong.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/bitsperlong.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/posix_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/stddef.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/stddef.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/uapi/asm/posix_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/posix_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kcsan-checks.h \
    $(wildcard include/config/KCSAN) \
    $(wildcard include/config/KCSAN_WEAK_MEMORY) \
    $(wildcard include/config/KCSAN_IGNORE_ATOMICS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/poison.h \
    $(wildcard include/config/ILLEGAL_POINTER_VALUE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/const.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/vdso/const.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/const.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/barrier.h \
    $(wildcard include/config/ARM64_PSEUDO_NMI) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/alternative-macros.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/vdso/bits.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/cpucaps.h \
    $(wildcard include/config/ARM64_PAN) \
    $(wildcard include/config/ARM64_EPAN) \
    $(wildcard include/config/ARM64_SVE) \
    $(wildcard include/config/ARM64_SME) \
    $(wildcard include/config/ARM64_CNP) \
    $(wildcard include/config/ARM64_MTE) \
    $(wildcard include/config/ARM64_BTI) \
    $(wildcard include/config/ARM64_TLB_RANGE) \
    $(wildcard include/config/ARM64_POE) \
    $(wildcard include/config/ARM64_GCS) \
    $(wildcard include/config/ARM64_HAFT) \
    $(wildcard include/config/UNMAP_KERNEL_AT_EL0) \
    $(wildcard include/config/ARM64_ERRATUM_843419) \
    $(wildcard include/config/ARM64_ERRATUM_1742098) \
    $(wildcard include/config/ARM64_ERRATUM_2645198) \
    $(wildcard include/config/ARM64_ERRATUM_2658417) \
    $(wildcard include/config/CAVIUM_ERRATUM_23154) \
    $(wildcard include/config/NVIDIA_CARMEL_CNP_ERRATUM) \
    $(wildcard include/config/ARM64_WORKAROUND_REPEAT_TLBI) \
    $(wildcard include/config/ARM64_ERRATUM_3194386) \
    $(wildcard include/config/HW_PERF_EVENTS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/cpucap-defs.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/insn-def.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/brk-imm.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/stringify.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/barrier.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/stat.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/stat.h \
    $(wildcard include/config/COMPAT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/uapi/asm/stat.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/stat.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/time.h \
    $(wildcard include/config/POSIX_TIMERS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cache.h \
    $(wildcard include/config/ARCH_HAS_CACHE_LINE_SIZE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/kernel.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/sysinfo.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/cache.h \
    $(wildcard include/config/KASAN_HW_TAGS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bitops.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bits.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/bits.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/typecheck.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/generic-non-atomic.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/bitops.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/builtin-__ffs.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/builtin-ffs.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/builtin-__fls.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/builtin-fls.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/ffz.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/fls64.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/sched.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/hweight.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/arch_hweight.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/const_hweight.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/atomic.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/atomic.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/atomic.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/cmpxchg.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/lse.h \
    $(wildcard include/config/ARM64_LSE_ATOMICS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/atomic_ll_sc.h \
    $(wildcard include/config/CC_HAS_K_CONSTRAINT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/export.h \
    $(wildcard include/config/MODVERSIONS) \
    $(wildcard include/config/GENDWARFKSYMS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/linkage.h \
    $(wildcard include/config/ARCH_USE_SYM_ANNOTATIONS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/linkage.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/alternative.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/init.h \
    $(wildcard include/config/MEMORY_HOTPLUG) \
    $(wildcard include/config/HAVE_ARCH_PREL32_RELOCATIONS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/atomic_lse.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/atomic/atomic-arch-fallback.h \
    $(wildcard include/config/GENERIC_ATOMIC64) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/atomic/atomic-long.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/atomic/atomic-instrumented.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/instrumented.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kmsan-checks.h \
    $(wildcard include/config/KMSAN) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/instrumented-atomic.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/lock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/instrumented-lock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/non-atomic.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/non-instrumented-non-atomic.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/le.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/uapi/asm/byteorder.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/byteorder/little_endian.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/byteorder/little_endian.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/swab.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/swab.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/uapi/asm/swab.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/swab.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/byteorder/generic.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bitops/ext2-atomic-setbit.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kasan-enabled.h \
    $(wildcard include/config/KASAN) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/static_key.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/jump_label.h \
    $(wildcard include/config/HAVE_ARCH_JUMP_LABEL_RELATIVE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cleanup.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/jump_label.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/insn.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/cputype.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/sysreg.h \
    $(wildcard include/config/BROKEN_GAS_INST) \
    $(wildcard include/config/ARM64_PA_BITS_52) \
    $(wildcard include/config/ARM64_4K_PAGES) \
    $(wildcard include/config/ARM64_16K_PAGES) \
    $(wildcard include/config/ARM64_64K_PAGES) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kasan-tags.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/gpr-num.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/sysreg-defs.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bitfield.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/mte-def.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/math64.h \
    $(wildcard include/config/ARCH_SUPPORTS_INT128) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/math.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/div64.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/div64.h \
    $(wildcard include/config/CC_OPTIMIZE_FOR_PERFORMANCE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/vdso/math64.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/time64.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/vdso/time64.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/time.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/time_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/time32.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/timex.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/timex.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/param.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/uapi/asm/param.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/param.h \
    $(wildcard include/config/HZ) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/param.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/timex.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/arch_timer.h \
    $(wildcard include/config/ARM_ARCH_TIMER_OOL_WORKAROUND) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/hwcap.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/uapi/asm/hwcap.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/cpufeature.h \
    $(wildcard include/config/ARM64_SW_TTBR0_PAN) \
    $(wildcard include/config/ARM64_DEBUG_PRIORITY_MASKING) \
    $(wildcard include/config/ARM64_BTI_KERNEL) \
    $(wildcard include/config/ARM64_PA_BITS) \
    $(wildcard include/config/ARM64_HW_AFDBM) \
    $(wildcard include/config/ARM64_AMU_EXTN) \
    $(wildcard include/config/ARM64_ACTLR_STATE) \
    $(wildcard include/config/ARM64_LPA2) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bug.h \
    $(wildcard include/config/PRINTK) \
    $(wildcard include/config/BUG_ON_DATA_CORRUPTION) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/bug.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/asm-bug.h \
    $(wildcard include/config/DEBUG_BUGVERBOSE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/bug.h \
    $(wildcard include/config/BUG) \
    $(wildcard include/config/GENERIC_BUG_RELATIVE_POINTERS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/instrumentation.h \
    $(wildcard include/config/NOINSTR_VALIDATION) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/once_lite.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/panic.h \
    $(wildcard include/config/PANIC_TIMEOUT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/printk.h \
    $(wildcard include/config/MESSAGE_LOGLEVEL_DEFAULT) \
    $(wildcard include/config/CONSOLE_LOGLEVEL_DEFAULT) \
    $(wildcard include/config/CONSOLE_LOGLEVEL_QUIET) \
    $(wildcard include/config/EARLY_PRINTK) \
    $(wildcard include/config/DYNAMIC_DEBUG) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/stdarg.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kern_levels.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/ratelimit_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/spinlock_types_raw.h \
    $(wildcard include/config/DEBUG_SPINLOCK) \
    $(wildcard include/config/DEBUG_LOCK_ALLOC) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/spinlock_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/qspinlock_types.h \
    $(wildcard include/config/NR_CPUS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/qrwlock_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/lockdep_types.h \
    $(wildcard include/config/PROVE_RAW_LOCK_NESTING) \
    $(wildcard include/config/LOCKDEP) \
    $(wildcard include/config/LOCK_STAT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kernel.h \
    $(wildcard include/config/PREEMPT_VOLUNTARY_BUILD) \
    $(wildcard include/config/PREEMPT_DYNAMIC) \
    $(wildcard include/config/HAVE_PREEMPT_DYNAMIC_CALL) \
    $(wildcard include/config/HAVE_PREEMPT_DYNAMIC_KEY) \
    $(wildcard include/config/PREEMPT_) \
    $(wildcard include/config/DEBUG_ATOMIC_SLEEP) \
    $(wildcard include/config/MMU) \
    $(wildcard include/config/PROVE_LOCKING) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/align.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/array_size.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/limits.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/limits.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/vdso/limits.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/hex.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kstrtox.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/log2.h \
    $(wildcard include/config/ARCH_HAS_ILOG2_U32) \
    $(wildcard include/config/ARCH_HAS_ILOG2_U64) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/minmax.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sprintf.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/static_call_types.h \
    $(wildcard include/config/HAVE_STATIC_CALL) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/instruction_pointer.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/wordpart.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cpumask.h \
    $(wildcard include/config/FORCE_NR_CPUS) \
    $(wildcard include/config/HOTPLUG_CPU) \
    $(wildcard include/config/DEBUG_PER_CPU_MAPS) \
    $(wildcard include/config/CPUMASK_OFFSTACK) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bitmap.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/errno.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/errno.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/uapi/asm/errno.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/errno.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/errno-base.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/find.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/string.h \
    $(wildcard include/config/BINARY_PRINTF) \
    $(wildcard include/config/FORTIFY_SOURCE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/args.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/err.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/overflow.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/string.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/string.h \
    $(wildcard include/config/ARCH_HAS_UACCESS_FLUSHCACHE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bitmap-str.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cpumask_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/threads.h \
    $(wildcard include/config/BASE_SMALL) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/gfp_types.h \
    $(wildcard include/config/SLAB_OBJ_EXT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/numa.h \
    $(wildcard include/config/NODES_SHIFT) \
    $(wildcard include/config/NUMA_KEEP_MEMINFO) \
    $(wildcard include/config/NUMA) \
    $(wildcard include/config/HAVE_ARCH_NODE_DEV_GROUP) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/sparsemem.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/pgtable-prot.h \
    $(wildcard include/config/HAVE_ARCH_USERFAULTFD_WP) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/memory.h \
    $(wildcard include/config/ARM64_VA_BITS) \
    $(wildcard include/config/KASAN_SHADOW_OFFSET) \
    $(wildcard include/config/VMAP_STACK) \
    $(wildcard include/config/RANDOMIZE_BASE) \
    $(wildcard include/config/DEBUG_VIRTUAL) \
    $(wildcard include/config/EFI) \
    $(wildcard include/config/ARM_GIC_V3_ITS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sizes.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/page-def.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/vdso/page.h \
    $(wildcard include/config/PAGE_SHIFT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/mmdebug.h \
    $(wildcard include/config/DEBUG_VM) \
    $(wildcard include/config/DEBUG_VM_IRQSOFF) \
    $(wildcard include/config/DEBUG_VM_PGFLAGS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/boot.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/sections.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/sections.h \
    $(wildcard include/config/HAVE_FUNCTION_DESCRIPTORS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/memory_model.h \
    $(wildcard include/config/FLATMEM) \
    $(wildcard include/config/SPARSEMEM_VMEMMAP) \
    $(wildcard include/config/SPARSEMEM) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/pfn.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/pgtable-hwdef.h \
    $(wildcard include/config/PGTABLE_LEVELS) \
    $(wildcard include/config/ARM64_CONT_PTE_SHIFT) \
    $(wildcard include/config/ARM64_CONT_PMD_SHIFT) \
    $(wildcard include/config/ARM64_VA_BITS_52) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/pgtable-types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/rsi.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/rsi_cmds.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/arm-smccc.h \
    $(wildcard include/config/HAVE_ARM_SMCCC) \
    $(wildcard include/config/ARM) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/rsi_smc.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/percpu.h \
    $(wildcard include/config/MEM_ALLOC_PROFILING) \
    $(wildcard include/config/RANDOM_KMALLOC_CACHES) \
    $(wildcard include/config/PAGE_SIZE_4KB) \
    $(wildcard include/config/NEED_PER_CPU_PAGE_FIRST_CHUNK) \
    $(wildcard include/config/HAVE_SETUP_PER_CPU_AREA) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/alloc_tag.h \
    $(wildcard include/config/MEM_ALLOC_PROFILING_DEBUG) \
    $(wildcard include/config/MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/codetag.h \
    $(wildcard include/config/CODE_TAGGING) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/preempt.h \
    $(wildcard include/config/PREEMPT_RT) \
    $(wildcard include/config/PREEMPT_COUNT) \
    $(wildcard include/config/DEBUG_PREEMPT) \
    $(wildcard include/config/TRACE_PREEMPT_TOGGLE) \
    $(wildcard include/config/PREEMPTION) \
    $(wildcard include/config/PREEMPT_NOTIFIERS) \
    $(wildcard include/config/PREEMPT_NONE) \
    $(wildcard include/config/PREEMPT_VOLUNTARY) \
    $(wildcard include/config/PREEMPT) \
    $(wildcard include/config/PREEMPT_LAZY) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/preempt.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/thread_info.h \
    $(wildcard include/config/THREAD_INFO_IN_TASK) \
    $(wildcard include/config/GENERIC_ENTRY) \
    $(wildcard include/config/ARCH_HAS_PREEMPT_LAZY) \
    $(wildcard include/config/HAVE_ARCH_WITHIN_STACK_FRAMES) \
    $(wildcard include/config/HARDENED_USERCOPY) \
    $(wildcard include/config/SH) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/restart_block.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/current.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/thread_info.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/stack_pointer.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/percpu.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/percpu.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/percpu-defs.h \
    $(wildcard include/config/DEBUG_FORCE_WEAK_PER_CPU) \
    $(wildcard include/config/AMD_MEM_ENCRYPT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/smp.h \
    $(wildcard include/config/UP_LATE_INIT) \
    $(wildcard include/config/CSD_LOCK_WAIT_DEBUG) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/smp_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/llist.h \
    $(wildcard include/config/ARCH_HAVE_NMI_SAFE_CMPXCHG) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/smp.h \
    $(wildcard include/config/ARM64_ACPI_PARKING_PROTOCOL) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/irqflags.h \
    $(wildcard include/config/TRACE_IRQFLAGS) \
    $(wildcard include/config/IRQSOFF_TRACER) \
    $(wildcard include/config/PREEMPT_TRACER) \
    $(wildcard include/config/DEBUG_IRQFLAGS) \
    $(wildcard include/config/TRACE_IRQFLAGS_SUPPORT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/irqflags_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/irqflags.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/ptrace.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/uapi/asm/ptrace.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/uapi/asm/sve_context.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/irqchip/arm-gic-v3-prio.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/stacktrace/frame.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched.h \
    $(wildcard include/config/VIRT_CPU_ACCOUNTING_NATIVE) \
    $(wildcard include/config/SCHED_INFO) \
    $(wildcard include/config/SCHEDSTATS) \
    $(wildcard include/config/SCHED_CORE) \
    $(wildcard include/config/FAIR_GROUP_SCHED) \
    $(wildcard include/config/RT_GROUP_SCHED) \
    $(wildcard include/config/RT_MUTEXES) \
    $(wildcard include/config/UCLAMP_TASK) \
    $(wildcard include/config/UCLAMP_BUCKETS_COUNT) \
    $(wildcard include/config/KMAP_LOCAL) \
    $(wildcard include/config/SCHED_CLASS_EXT) \
    $(wildcard include/config/CGROUP_SCHED) \
    $(wildcard include/config/BLK_DEV_IO_TRACE) \
    $(wildcard include/config/PREEMPT_RCU) \
    $(wildcard include/config/TASKS_RCU) \
    $(wildcard include/config/TASKS_TRACE_RCU) \
    $(wildcard include/config/MEMCG_V1) \
    $(wildcard include/config/LRU_GEN) \
    $(wildcard include/config/COMPAT_BRK) \
    $(wildcard include/config/CGROUPS) \
    $(wildcard include/config/BLK_CGROUP) \
    $(wildcard include/config/PSI) \
    $(wildcard include/config/PAGE_OWNER) \
    $(wildcard include/config/EVENTFD) \
    $(wildcard include/config/ARCH_HAS_CPU_PASID) \
    $(wildcard include/config/X86_BUS_LOCK_DETECT) \
    $(wildcard include/config/TASK_DELAY_ACCT) \
    $(wildcard include/config/STACKPROTECTOR) \
    $(wildcard include/config/ARCH_HAS_SCALED_CPUTIME) \
    $(wildcard include/config/VIRT_CPU_ACCOUNTING_GEN) \
    $(wildcard include/config/NO_HZ_FULL) \
    $(wildcard include/config/POSIX_CPUTIMERS) \
    $(wildcard include/config/POSIX_CPU_TIMERS_TASK_WORK) \
    $(wildcard include/config/KEYS) \
    $(wildcard include/config/SYSVIPC) \
    $(wildcard include/config/DETECT_HUNG_TASK) \
    $(wildcard include/config/IO_URING) \
    $(wildcard include/config/AUDIT) \
    $(wildcard include/config/AUDITSYSCALL) \
    $(wildcard include/config/DEBUG_MUTEXES) \
    $(wildcard include/config/UBSAN) \
    $(wildcard include/config/UBSAN_TRAP) \
    $(wildcard include/config/COMPACTION) \
    $(wildcard include/config/TASK_XACCT) \
    $(wildcard include/config/CPUSETS) \
    $(wildcard include/config/X86_CPU_RESCTRL) \
    $(wildcard include/config/FUTEX) \
    $(wildcard include/config/PERF_EVENTS) \
    $(wildcard include/config/NUMA_BALANCING) \
    $(wildcard include/config/RSEQ) \
    $(wildcard include/config/DEBUG_RSEQ) \
    $(wildcard include/config/SCHED_MM_CID) \
    $(wildcard include/config/FAULT_INJECTION) \
    $(wildcard include/config/LATENCYTOP) \
    $(wildcard include/config/FUNCTION_GRAPH_TRACER) \
    $(wildcard include/config/MEMCG) \
    $(wildcard include/config/UPROBES) \
    $(wildcard include/config/BCACHE) \
    $(wildcard include/config/SECURITY) \
    $(wildcard include/config/BPF_SYSCALL) \
    $(wildcard include/config/GCC_PLUGIN_STACKLEAK) \
    $(wildcard include/config/X86_MCE) \
    $(wildcard include/config/KRETPROBES) \
    $(wildcard include/config/RETHOOK) \
    $(wildcard include/config/ARCH_HAS_PARANOID_L1D_FLUSH) \
    $(wildcard include/config/RV) \
    $(wildcard include/config/USER_EVENTS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/sched.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/processor.h \
    $(wildcard include/config/KUSER_HELPERS) \
    $(wildcard include/config/ARM64_FORCE_52BIT) \
    $(wildcard include/config/HAVE_HW_BREAKPOINT) \
    $(wildcard include/config/ARM64_TAGGED_ADDR_ABI) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/vdso/processor.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/vdso/processor.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/hw_breakpoint.h \
    $(wildcard include/config/CPU_PM) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/virt.h \
    $(wildcard include/config/KVM) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/kasan.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/mte-kasan.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/pointer_auth.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/prctl.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/random.h \
    $(wildcard include/config/VMGENID) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/random.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/ioctl.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/uapi/asm/ioctl.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/ioctl.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/ioctl.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/irqnr.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/irqnr.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/spectre.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/fpsimd.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/uapi/asm/sigcontext.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/pid_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sem_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/shm.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/page.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/personality.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/personality.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/getorder.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/shmparam.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/shmparam.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kmsan_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/mutex_types.h \
    $(wildcard include/config/MUTEX_SPIN_ON_OWNER) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/osq_lock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/spinlock_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rwlock_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/plist_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/hrtimer_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/timerqueue_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rbtree_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/timer_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/seccomp_types.h \
    $(wildcard include/config/SECCOMP) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/nodemask_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/refcount_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/resource.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/resource.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/uapi/asm/resource.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/resource.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/resource.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/latencytop.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/prio.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/signal_types.h \
    $(wildcard include/config/OLD_SIGACTION) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/signal.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/signal.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/uapi/asm/signal.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/signal.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/signal.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/signal-defs.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/uapi/asm/siginfo.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/siginfo.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/syscall_user_dispatch_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/mm_types_task.h \
    $(wildcard include/config/ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/tlbbatch.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/netdevice_xmit.h \
    $(wildcard include/config/NET_EGRESS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/task_io_accounting.h \
    $(wildcard include/config/TASK_IO_ACCOUNTING) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/posix-timers_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/rseq.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/seqlock_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kcsan.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rv.h \
    $(wildcard include/config/RV_REACTORS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/livepatch_sched.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/uidgid_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/kmap_size.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/kmap_size.h \
    $(wildcard include/config/DEBUG_KMAP_LOCAL) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/ext.h \
    $(wildcard include/config/EXT_GROUP_SCHED) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/spinlock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bottom_half.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/lockdep.h \
    $(wildcard include/config/DEBUG_LOCKING_API_SELFTESTS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/mmiowb.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/mmiowb.h \
    $(wildcard include/config/MMIOWB) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/spinlock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/qspinlock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/qspinlock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/qrwlock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/qrwlock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rwlock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/spinlock_api_smp.h \
    $(wildcard include/config/INLINE_SPIN_LOCK) \
    $(wildcard include/config/INLINE_SPIN_LOCK_BH) \
    $(wildcard include/config/INLINE_SPIN_LOCK_IRQ) \
    $(wildcard include/config/INLINE_SPIN_LOCK_IRQSAVE) \
    $(wildcard include/config/INLINE_SPIN_TRYLOCK) \
    $(wildcard include/config/INLINE_SPIN_TRYLOCK_BH) \
    $(wildcard include/config/UNINLINE_SPIN_UNLOCK) \
    $(wildcard include/config/INLINE_SPIN_UNLOCK_BH) \
    $(wildcard include/config/INLINE_SPIN_UNLOCK_IRQ) \
    $(wildcard include/config/INLINE_SPIN_UNLOCK_IRQRESTORE) \
    $(wildcard include/config/GENERIC_LOCKBREAK) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rwlock_api_smp.h \
    $(wildcard include/config/INLINE_READ_LOCK) \
    $(wildcard include/config/INLINE_WRITE_LOCK) \
    $(wildcard include/config/INLINE_READ_LOCK_BH) \
    $(wildcard include/config/INLINE_WRITE_LOCK_BH) \
    $(wildcard include/config/INLINE_READ_LOCK_IRQ) \
    $(wildcard include/config/INLINE_WRITE_LOCK_IRQ) \
    $(wildcard include/config/INLINE_READ_LOCK_IRQSAVE) \
    $(wildcard include/config/INLINE_WRITE_LOCK_IRQSAVE) \
    $(wildcard include/config/INLINE_READ_TRYLOCK) \
    $(wildcard include/config/INLINE_WRITE_TRYLOCK) \
    $(wildcard include/config/INLINE_READ_UNLOCK) \
    $(wildcard include/config/INLINE_WRITE_UNLOCK) \
    $(wildcard include/config/INLINE_READ_UNLOCK_BH) \
    $(wildcard include/config/INLINE_WRITE_UNLOCK_BH) \
    $(wildcard include/config/INLINE_READ_UNLOCK_IRQ) \
    $(wildcard include/config/INLINE_WRITE_UNLOCK_IRQ) \
    $(wildcard include/config/INLINE_READ_UNLOCK_IRQRESTORE) \
    $(wildcard include/config/INLINE_WRITE_UNLOCK_IRQRESTORE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/clocksource/arm_arch_timer.h \
    $(wildcard include/config/ARM_ARCH_TIMER) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/timecounter.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/timex.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/vdso/time32.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/vdso/time.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/compat.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/compat.h \
    $(wildcard include/config/COMPAT_FOR_U64_ALIGNMENT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/task_stack.h \
    $(wildcard include/config/STACK_GROWSUP) \
    $(wildcard include/config/DEBUG_STACK_USAGE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/magic.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/refcount.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kasan.h \
    $(wildcard include/config/KASAN_STACK) \
    $(wildcard include/config/KASAN_VMALLOC) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/stat.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/uidgid.h \
    $(wildcard include/config/MULTIUSER) \
    $(wildcard include/config/USER_NS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/highuid.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/buildid.h \
    $(wildcard include/config/VMCORE_INFO) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kmod.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/umh.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/gfp.h \
    $(wildcard include/config/HIGHMEM) \
    $(wildcard include/config/ZONE_DMA) \
    $(wildcard include/config/ZONE_DMA32) \
    $(wildcard include/config/ZONE_DEVICE) \
    $(wildcard include/config/CONTIG_ALLOC) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/mmzone.h \
    $(wildcard include/config/ARCH_FORCE_MAX_ORDER) \
    $(wildcard include/config/CMA) \
    $(wildcard include/config/MEMORY_ISOLATION) \
    $(wildcard include/config/ZSMALLOC) \
    $(wildcard include/config/UNACCEPTED_MEMORY) \
    $(wildcard include/config/IOMMU_SUPPORT) \
    $(wildcard include/config/SWAP) \
    $(wildcard include/config/HUGETLB_PAGE) \
    $(wildcard include/config/TRANSPARENT_HUGEPAGE) \
    $(wildcard include/config/LRU_GEN_STATS) \
    $(wildcard include/config/LRU_GEN_WALKS_MMU) \
    $(wildcard include/config/MEMORY_FAILURE) \
    $(wildcard include/config/PAGE_EXTENSION) \
    $(wildcard include/config/DEFERRED_STRUCT_PAGE_INIT) \
    $(wildcard include/config/HAVE_MEMORYLESS_NODES) \
    $(wildcard include/config/SPARSEMEM_EXTREME) \
    $(wildcard include/config/HAVE_ARCH_PFN_VALID) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/list_nulls.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/wait.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/seqlock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/mutex.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/debug_locks.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/nodemask.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/pageblock-flags.h \
    $(wildcard include/config/HUGETLB_PAGE_SIZE_VARIABLE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/page-flags-layout.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/generated/bounds.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/mm_types.h \
    $(wildcard include/config/HAVE_ALIGNED_STRUCT_PAGE) \
    $(wildcard include/config/HUGETLB_PMD_PAGE_TABLE_SHARING) \
    $(wildcard include/config/USERFAULTFD) \
    $(wildcard include/config/ANON_VMA_NAME) \
    $(wildcard include/config/PER_VMA_LOCK) \
    $(wildcard include/config/HAVE_ARCH_COMPAT_MMAP_BASES) \
    $(wildcard include/config/MEMBARRIER) \
    $(wildcard include/config/AIO) \
    $(wildcard include/config/MMU_NOTIFIER) \
    $(wildcard include/config/SPLIT_PMD_PTLOCKS) \
    $(wildcard include/config/IOMMU_MM_DATA) \
    $(wildcard include/config/KSM) \
    $(wildcard include/config/CORE_DUMP_DEFAULT_ELF_HEADERS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/auxvec.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/auxvec.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/uapi/asm/auxvec.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kref.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rbtree.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rcupdate.h \
    $(wildcard include/config/TINY_RCU) \
    $(wildcard include/config/RCU_STRICT_GRACE_PERIOD) \
    $(wildcard include/config/RCU_LAZY) \
    $(wildcard include/config/TASKS_RCU_GENERIC) \
    $(wildcard include/config/RCU_STALL_COMMON) \
    $(wildcard include/config/KVM_XFER_TO_GUEST_WORK) \
    $(wildcard include/config/RCU_NOCB_CPU) \
    $(wildcard include/config/TASKS_RUDE_RCU) \
    $(wildcard include/config/TREE_RCU) \
    $(wildcard include/config/DEBUG_OBJECTS_RCU_HEAD) \
    $(wildcard include/config/PROVE_RCU) \
    $(wildcard include/config/ARCH_WEAK_RELEASE_ACQUIRE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/context_tracking_irq.h \
    $(wildcard include/config/CONTEXT_TRACKING_IDLE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rcutree.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/maple_tree.h \
    $(wildcard include/config/MAPLE_RCU_DISABLED) \
    $(wildcard include/config/DEBUG_MAPLE_TREE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rwsem.h \
    $(wildcard include/config/RWSEM_SPIN_ON_OWNER) \
    $(wildcard include/config/DEBUG_RWSEMS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/completion.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/swait.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/uprobes.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/timer.h \
    $(wildcard include/config/DEBUG_OBJECTS_TIMERS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/ktime.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/jiffies.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/vdso/jiffies.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/generated/timeconst.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/vdso/ktime.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/timekeeping.h \
    $(wildcard include/config/GENERIC_CMOS_UPDATE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/clocksource_ids.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/debugobjects.h \
    $(wildcard include/config/DEBUG_OBJECTS) \
    $(wildcard include/config/DEBUG_OBJECTS_FREE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/workqueue.h \
    $(wildcard include/config/DEBUG_OBJECTS_WORK) \
    $(wildcard include/config/FREEZER) \
    $(wildcard include/config/WQ_WATCHDOG) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/workqueue_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/percpu_counter.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/mmu.h \
    $(wildcard include/config/ARM64_E0PD) \
    $(wildcard include/config/CAVIUM_ERRATUM_27456) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/page-flags.h \
    $(wildcard include/config/PAGE_IDLE_FLAG) \
    $(wildcard include/config/ARCH_USES_PG_ARCH_2) \
    $(wildcard include/config/ARCH_USES_PG_ARCH_3) \
    $(wildcard include/config/HUGETLB_PAGE_OPTIMIZE_VMEMMAP) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/local_lock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/local_lock_internal.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/zswap.h \
    $(wildcard include/config/ZSWAP) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/memory_hotplug.h \
    $(wildcard include/config/ARCH_HAS_ADD_PAGES) \
    $(wildcard include/config/MEMORY_HOTREMOVE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/notifier.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/srcu.h \
    $(wildcard include/config/TINY_SRCU) \
    $(wildcard include/config/NEED_SRCU_NMI_SAFE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rcu_segcblist.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/srcutree.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rcu_node_tree.h \
    $(wildcard include/config/RCU_FANOUT) \
    $(wildcard include/config/RCU_FANOUT_LEAF) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/mmzone.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/mmzone.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/topology.h \
    $(wildcard include/config/USE_PERCPU_NUMA_NODE_ID) \
    $(wildcard include/config/SCHED_SMT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/arch_topology.h \
    $(wildcard include/config/GENERIC_ARCH_TOPOLOGY) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/topology.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/numa.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/numa.h \
    $(wildcard include/config/NUMA_EMU) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/topology.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sysctl.h \
    $(wildcard include/config/SYSCTL) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/sysctl.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/elf.h \
    $(wildcard include/config/ARCH_HAVE_EXTRA_ELF_NOTES) \
    $(wildcard include/config/ARCH_USE_GNU_PROPERTY) \
    $(wildcard include/config/ARCH_HAVE_ELF_PROT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/elf.h \
    $(wildcard include/config/COMPAT_VDSO) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/user.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/user.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/elf.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/elf-em.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/fs.h \
    $(wildcard include/config/FANOTIFY_ACCESS_PERMISSIONS) \
    $(wildcard include/config/READ_ONLY_THP_FOR_FS) \
    $(wildcard include/config/FS_POSIX_ACL) \
    $(wildcard include/config/CGROUP_WRITEBACK) \
    $(wildcard include/config/IMA) \
    $(wildcard include/config/FILE_LOCKING) \
    $(wildcard include/config/FSNOTIFY) \
    $(wildcard include/config/FS_ENCRYPTION) \
    $(wildcard include/config/FS_VERITY) \
    $(wildcard include/config/EPOLL) \
    $(wildcard include/config/UNICODE) \
    $(wildcard include/config/QUOTA) \
    $(wildcard include/config/FS_DAX) \
    $(wildcard include/config/BLOCK) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/wait_bit.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kdev_t.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/kdev_t.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/dcache.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rculist.h \
    $(wildcard include/config/PROVE_RCU_LIST) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rculist_bl.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/list_bl.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bit_spinlock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/lockref.h \
    $(wildcard include/config/ARCH_USE_CMPXCHG_LOCKREF) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/stringhash.h \
    $(wildcard include/config/DCACHE_WORD_ACCESS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/hash.h \
    $(wildcard include/config/HAVE_ARCH_HASH) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/path.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/list_lru.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/shrinker.h \
    $(wildcard include/config/SHRINKER_DEBUG) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/xarray.h \
    $(wildcard include/config/XARRAY_MULTI) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/mm.h \
    $(wildcard include/config/MMU_LAZY_TLB_REFCOUNT) \
    $(wildcard include/config/ARCH_HAS_MEMBARRIER_CALLBACKS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sync_core.h \
    $(wildcard include/config/ARCH_HAS_SYNC_CORE_BEFORE_USERMODE) \
    $(wildcard include/config/ARCH_HAS_PREPARE_SYNC_CORE_CMD) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/coredump.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/radix-tree.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/pid.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/capability.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/capability.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/semaphore.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/fcntl.h \
    $(wildcard include/config/ARCH_32BIT_OFF_T) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/fcntl.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/uapi/asm/fcntl.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/fcntl.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/openat2.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/migrate_mode.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/percpu-rwsem.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rcuwait.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/signal.h \
    $(wildcard include/config/SCHED_AUTOGROUP) \
    $(wildcard include/config/BSD_PROCESS_ACCT) \
    $(wildcard include/config/TASKSTATS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/signal.h \
    $(wildcard include/config/DYNAMIC_SIGFRAME) \
    $(wildcard include/config/PROC_FS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/jobctl.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/task.h \
    $(wildcard include/config/HAVE_EXIT_THREAD) \
    $(wildcard include/config/ARCH_WANTS_DYNAMIC_TASK_STRUCT) \
    $(wildcard include/config/HAVE_ARCH_THREAD_STRUCT_WHITELIST) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/uaccess.h \
    $(wildcard include/config/ARCH_HAS_SUBPAGE_FAULTS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/fault-inject-usercopy.h \
    $(wildcard include/config/FAULT_INJECTION_USERCOPY) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/nospec.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/uaccess.h \
    $(wildcard include/config/CC_HAS_ASM_GOTO_OUTPUT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/kernel-pgtable.h \
    $(wildcard include/config/RELOCATABLE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/asm-extable.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/mte.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/extable.h \
    $(wildcard include/config/BPF_JIT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/access_ok.h \
    $(wildcard include/config/ALTERNATE_USER_ADDRESS_SPACE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cred.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/key.h \
    $(wildcard include/config/KEY_NOTIFICATIONS) \
    $(wildcard include/config/NET) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/assoc_array.h \
    $(wildcard include/config/ASSOCIATIVE_ARRAY) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/user.h \
    $(wildcard include/config/VFIO_PCI_ZDEV_KVM) \
    $(wildcard include/config/IOMMUFD) \
    $(wildcard include/config/WATCH_QUEUE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/ratelimit.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/posix-timers.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/alarmtimer.h \
    $(wildcard include/config/RTC_CLASS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/hrtimer.h \
    $(wildcard include/config/HIGH_RES_TIMERS) \
    $(wildcard include/config/TIME_LOW_RES) \
    $(wildcard include/config/TIMERFD) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/hrtimer_defs.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/timerqueue.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rcuref.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rcu_sync.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/delayed_call.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/uuid.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/errseq.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/ioprio.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/rt.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/iocontext.h \
    $(wildcard include/config/BLK_ICQ) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/ioprio.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/fs_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/mount.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/mnt_idmapping.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/slab.h \
    $(wildcard include/config/FAILSLAB) \
    $(wildcard include/config/KFENCE) \
    $(wildcard include/config/SLUB_TINY) \
    $(wildcard include/config/SLUB_DEBUG) \
    $(wildcard include/config/SLAB_FREELIST_HARDENED) \
    $(wildcard include/config/SLAB_BUCKETS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/percpu-refcount.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rw_hint.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/file_ref.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/unicode.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/fs.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/quota.h \
    $(wildcard include/config/QUOTA_NETLINK_INTERFACE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/dqblk_xfs.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/dqblk_v1.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/dqblk_v2.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/dqblk_qtree.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/projid.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/quota.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kobject.h \
    $(wildcard include/config/UEVENT_HELPER) \
    $(wildcard include/config/DEBUG_KOBJECT_RELEASE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sysfs.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kernfs.h \
    $(wildcard include/config/KERNFS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/idr.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kobject_ns.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/moduleparam.h \
    $(wildcard include/config/ALPHA) \
    $(wildcard include/config/PPC64) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rbtree_latch.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/error-injection.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/error-injection.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/tracepoint-defs.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/dynamic_debug.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/module.h \
    $(wildcard include/config/DYNAMIC_FTRACE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/module.h \
    $(wildcard include/config/HAVE_MOD_ARCH_SPECIFIC) \
    $(wildcard include/config/MODULES_USE_ELF_REL) \
    $(wildcard include/config/MODULES_USE_ELF_RELA) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kallsyms.h \
    $(wildcard include/config/KALLSYMS_ALL) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/mm.h \
    $(wildcard include/config/HAVE_ARCH_MMAP_RND_BITS) \
    $(wildcard include/config/HAVE_ARCH_MMAP_RND_COMPAT_BITS) \
    $(wildcard include/config/MEM_SOFT_DIRTY) \
    $(wildcard include/config/ARCH_USES_HIGH_VMA_FLAGS) \
    $(wildcard include/config/ARCH_HAS_PKEYS) \
    $(wildcard include/config/ARCH_PKEY_BITS) \
    $(wildcard include/config/X86_USER_SHADOW_STACK) \
    $(wildcard include/config/X86) \
    $(wildcard include/config/PARISC) \
    $(wildcard include/config/SPARC64) \
    $(wildcard include/config/HAVE_ARCH_USERFAULTFD_MINOR) \
    $(wildcard include/config/PPC32) \
    $(wildcard include/config/SHMEM) \
    $(wildcard include/config/MIGRATION) \
    $(wildcard include/config/ARCH_HAS_GIGANTIC_PAGE) \
    $(wildcard include/config/ARCH_HAS_PTE_SPECIAL) \
    $(wildcard include/config/ARCH_SUPPORTS_PMD_PFNMAP) \
    $(wildcard include/config/ARCH_SUPPORTS_PUD_PFNMAP) \
    $(wildcard include/config/ARCH_HAS_PTE_DEVMAP) \
    $(wildcard include/config/SPLIT_PTE_PTLOCKS) \
    $(wildcard include/config/HIGHPTE) \
    $(wildcard include/config/DEBUG_VM_RB) \
    $(wildcard include/config/PAGE_POISONING) \
    $(wildcard include/config/INIT_ON_ALLOC_DEFAULT_ON) \
    $(wildcard include/config/INIT_ON_FREE_DEFAULT_ON) \
    $(wildcard include/config/DEBUG_PAGEALLOC) \
    $(wildcard include/config/ARCH_WANT_OPTIMIZE_DAX_VMEMMAP) \
    $(wildcard include/config/HUGETLBFS) \
    $(wildcard include/config/MAPPING_DIRTY_HELPERS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/pgalloc_tag.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/mmap_lock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/range.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/page_ext.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/stacktrace.h \
    $(wildcard include/config/ARCH_STACKWALK) \
    $(wildcard include/config/STACKTRACE) \
    $(wildcard include/config/HAVE_RELIABLE_STACKTRACE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/page_ref.h \
    $(wildcard include/config/DEBUG_PAGE_REF) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/pgtable.h \
    $(wildcard include/config/ARCH_HAS_NONLEAF_PMD_YOUNG) \
    $(wildcard include/config/ARCH_HAS_HW_PTE_YOUNG) \
    $(wildcard include/config/GUP_GET_PXX_LOW_HIGH) \
    $(wildcard include/config/ARCH_WANT_PMD_MKWRITE) \
    $(wildcard include/config/HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD) \
    $(wildcard include/config/HAVE_ARCH_SOFT_DIRTY) \
    $(wildcard include/config/ARCH_ENABLE_THP_MIGRATION) \
    $(wildcard include/config/HAVE_ARCH_HUGE_VMAP) \
    $(wildcard include/config/X86_ESPFIX64) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/pgtable.h \
    $(wildcard include/config/PAGE_TABLE_CHECK) \
    $(wildcard include/config/ARM64_CONTPTE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/proc-fns.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/tlbflush.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/mmu_notifier.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/interval_tree.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/fixmap.h \
    $(wildcard include/config/ACPI_APEI_GHES) \
    $(wildcard include/config/ARM_SDE_INTERFACE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/fixmap.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/por.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/page_table_check.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/pgtable_uffd.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/memremap.h \
    $(wildcard include/config/DEVICE_PRIVATE) \
    $(wildcard include/config/PCI_P2PDMA) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/ioport.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cacheinfo.h \
    $(wildcard include/config/ACPI_PPTT) \
    $(wildcard include/config/ARCH_HAS_CPU_CACHE_ALIASING) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cpuhplock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/huge_mm.h \
    $(wildcard include/config/PGTABLE_HAS_HUGE_LEAVES) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/vmstat.h \
    $(wildcard include/config/VM_EVENT_COUNTERS) \
    $(wildcard include/config/DEBUG_TLBFLUSH) \
    $(wildcard include/config/PER_VMA_LOCK_STATS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/vm_event_item.h \
    $(wildcard include/config/MEMORY_BALLOON) \
    $(wildcard include/config/BALLOON_COMPACTION) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/syscalls.h \
    $(wildcard include/config/ARCH_HAS_SYSCALL_WRAPPER) \
    $(wildcard include/config/FTRACE_SYSCALLS) \
    $(wildcard include/config/ODD_RT_SIGACTION) \
    $(wildcard include/config/CLONE_BACKWARDS) \
    $(wildcard include/config/CLONE_BACKWARDS3) \
    $(wildcard include/config/ARCH_SPLIT_ARG64) \
    $(wildcard include/config/OLD_SIGSUSPEND) \
    $(wildcard include/config/OLD_SIGSUSPEND3) \
    $(wildcard include/config/ADVISE_SYSCALLS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/aio_abi.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sem.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/sem.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/ipc.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rhashtable-types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/ipc.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/uapi/asm/ipcbuf.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/ipcbuf.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/uapi/asm/sembuf.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/sembuf.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/unistd.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/unistd.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/uapi/asm/unistd_64.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/trace/syscall.h \
    $(wildcard include/config/HAVE_SYSCALL_TRACEPOINTS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/tracepoint.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rcupdate_trace.h \
    $(wildcard include/config/TASKS_TRACE_RCU_READ_MB) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/static_call.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cpu.h \
    $(wildcard include/config/GENERIC_CPU_DEVICES) \
    $(wildcard include/config/PM_SLEEP_SMP) \
    $(wildcard include/config/PM_SLEEP_SMP_NONZERO_CPU) \
    $(wildcard include/config/ARCH_HAS_CPU_FINALIZE_INIT) \
    $(wildcard include/config/CPU_MITIGATIONS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/node.h \
    $(wildcard include/config/HMEM_REPORTING) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/device.h \
    $(wildcard include/config/HAS_IOMEM) \
    $(wildcard include/config/GENERIC_MSI_IRQ) \
    $(wildcard include/config/ENERGY_MODEL) \
    $(wildcard include/config/PINCTRL) \
    $(wildcard include/config/ARCH_HAS_DMA_OPS) \
    $(wildcard include/config/DMA_DECLARE_COHERENT) \
    $(wildcard include/config/DMA_CMA) \
    $(wildcard include/config/SWIOTLB) \
    $(wildcard include/config/SWIOTLB_DYNAMIC) \
    $(wildcard include/config/ARCH_HAS_SYNC_DMA_FOR_DEVICE) \
    $(wildcard include/config/ARCH_HAS_SYNC_DMA_FOR_CPU) \
    $(wildcard include/config/ARCH_HAS_SYNC_DMA_FOR_CPU_ALL) \
    $(wildcard include/config/DMA_OPS_BYPASS) \
    $(wildcard include/config/DMA_NEED_SYNC) \
    $(wildcard include/config/IOMMU_DMA) \
    $(wildcard include/config/PM_SLEEP) \
    $(wildcard include/config/OF) \
    $(wildcard include/config/DEVTMPFS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/dev_printk.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/energy_model.h \
    $(wildcard include/config/SCHED_DEBUG) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/cpufreq.h \
    $(wildcard include/config/CPU_FREQ) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/topology.h \
    $(wildcard include/config/SCHED_CLUSTER) \
    $(wildcard include/config/SCHED_MC) \
    $(wildcard include/config/CPU_FREQ_GOV_SCHEDUTIL) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/idle.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sched/sd_flags.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/klist.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/pm.h \
    $(wildcard include/config/VT_CONSOLE_SLEEP) \
    $(wildcard include/config/CXL_SUSPEND) \
    $(wildcard include/config/PM) \
    $(wildcard include/config/PM_CLK) \
    $(wildcard include/config/PM_GENERIC_DOMAINS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/device/bus.h \
    $(wildcard include/config/ACPI) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/device/class.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/device/driver.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/device.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/pm_wakeup.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cpuhotplug.h \
    $(wildcard include/config/HOTPLUG_CORE_SYNC_DEAD) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cpu_smt.h \
    $(wildcard include/config/HOTPLUG_SMT) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/trace_events.h \
    $(wildcard include/config/DYNAMIC_EVENTS) \
    $(wildcard include/config/HIST_TRIGGERS) \
    $(wildcard include/config/KPROBE_EVENTS) \
    $(wildcard include/config/UPROBE_EVENTS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/ring_buffer.h \
    $(wildcard include/config/RING_BUFFER_ALLOW_SWAP) \
    $(wildcard include/config/RING_BUFFER) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/seq_file.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/string_helpers.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/ctype.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/string_choices.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/poll.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/poll.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/uapi/asm/poll.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/poll.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/eventpoll.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/trace_mmap.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/trace_seq.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/seq_buf.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/hardirq.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/context_tracking_state.h \
    $(wildcard include/config/CONTEXT_TRACKING_USER) \
    $(wildcard include/config/CONTEXT_TRACKING) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/ftrace_irq.h \
    $(wildcard include/config/HWLAT_TRACER) \
    $(wildcard include/config/OSNOISE_TRACER) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/vtime.h \
    $(wildcard include/config/VIRT_CPU_ACCOUNTING) \
    $(wildcard include/config/IRQ_TIME_ACCOUNTING) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/hardirq.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/irq.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/irq.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/kvm_arm.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/esr.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/hardirq.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/irq.h \
    $(wildcard include/config/GENERIC_IRQ_EFFECTIVE_AFF_MASK) \
    $(wildcard include/config/GENERIC_IRQ_IPI) \
    $(wildcard include/config/IRQ_DOMAIN_HIERARCHY) \
    $(wildcard include/config/DEPRECATED_IRQ_CPU_ONOFFLINE) \
    $(wildcard include/config/GENERIC_IRQ_MIGRATION) \
    $(wildcard include/config/GENERIC_PENDING_IRQ) \
    $(wildcard include/config/HARDIRQS_SW_RESEND) \
    $(wildcard include/config/GENERIC_IRQ_LEGACY) \
    $(wildcard include/config/GENERIC_IRQ_CHIP) \
    $(wildcard include/config/GENERIC_IRQ_MULTI_HANDLER) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/irqhandler.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/irqreturn.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/io.h \
    $(wildcard include/config/HAS_IOPORT_MAP) \
    $(wildcard include/config/PCI) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/io.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/early_ioremap.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/early_ioremap.h \
    $(wildcard include/config/GENERIC_EARLY_IOREMAP) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/io.h \
    $(wildcard include/config/GENERIC_IOMAP) \
    $(wildcard include/config/TRACE_MMIO_ACCESS) \
    $(wildcard include/config/HAS_IOPORT) \
    $(wildcard include/config/GENERIC_IOREMAP) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/pci_iomap.h \
    $(wildcard include/config/NO_GENERIC_PCI_IOPORT_MAP) \
    $(wildcard include/config/GENERIC_PCI_IOMAP) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/logic_pio.h \
    $(wildcard include/config/INDIRECT_PIO) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/fwnode.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/irq_regs.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/irq_regs.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/irqdesc.h \
    $(wildcard include/config/GENERIC_IRQ_STAT_SNAPSHOT) \
    $(wildcard include/config/GENERIC_IRQ_DEBUGFS) \
    $(wildcard include/config/SPARSE_IRQ) \
    $(wildcard include/config/IRQ_DOMAIN) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/hw_irq.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/hw_irq.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/perf_event.h \
    $(wildcard include/config/FUNCTION_TRACER) \
    $(wildcard include/config/CGROUP_PERF) \
    $(wildcard include/config/GUEST_PERF_EVENTS) \
    $(wildcard include/config/CPU_SUP_INTEL) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/perf_event.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/bpf_perf_event.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/uapi/asm/bpf_perf_event.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/perf_event.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/local64.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/local64.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/local.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/local.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/pid_namespace.h \
    $(wildcard include/config/MEMFD_CREATE) \
    $(wildcard include/config/PID_NS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/nsproxy.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/ns_common.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/ftrace.h \
    $(wildcard include/config/HAVE_FUNCTION_GRAPH_FREGS) \
    $(wildcard include/config/HAVE_DYNAMIC_FTRACE_WITH_ARGS) \
    $(wildcard include/config/HAVE_FTRACE_REGS_HAVING_PT_REGS) \
    $(wildcard include/config/HAVE_REGS_AND_STACK_ACCESS_API) \
    $(wildcard include/config/DYNAMIC_FTRACE_WITH_REGS) \
    $(wildcard include/config/DYNAMIC_FTRACE_WITH_ARGS) \
    $(wildcard include/config/DYNAMIC_FTRACE_WITH_DIRECT_CALLS) \
    $(wildcard include/config/STACK_TRACER) \
    $(wildcard include/config/DYNAMIC_FTRACE_WITH_CALL_OPS) \
    $(wildcard include/config/FRAME_POINTER) \
    $(wildcard include/config/FUNCTION_GRAPH_RETVAL) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/trace_recursion.h \
    $(wildcard include/config/FTRACE_RECORD_RECURSION) \
    $(wildcard include/config/FTRACE_VALIDATE_RCU_IS_WATCHING) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/interrupt.h \
    $(wildcard include/config/IRQ_FORCED_THREADING) \
    $(wildcard include/config/GENERIC_IRQ_PROBE) \
    $(wildcard include/config/IRQ_TIMINGS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/trace_clock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/trace_clock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/trace_clock.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/ptrace.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/ptrace.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/seccomp.h \
    $(wildcard include/config/HAVE_ARCH_SECCOMP_FILTER) \
    $(wildcard include/config/SECCOMP_FILTER) \
    $(wildcard include/config/CHECKPOINT_RESTORE) \
    $(wildcard include/config/SECCOMP_CACHE_DEBUG) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/seccomp.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/seccomp.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/unistd_compat_32.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/seccomp.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/ftrace.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/compat.h \
    $(wildcard include/config/X86_X32_ABI) \
    $(wildcard include/config/COMPAT_OLD_SIGACTION) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/socket.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/uapi/asm/socket.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/socket.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/uapi/asm/sockios.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/asm-generic/sockios.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/sockios.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/uio.h \
    $(wildcard include/config/ARCH_HAS_COPY_MC) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/uio.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/socket.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/if.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/libc-compat.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/hdlc/ioctl.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/syscall_wrapper.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/irq_work.h \
    $(wildcard include/config/IRQ_WORK) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/irq_work.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/jump_label_ratelimit.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/perf_regs.h \
    $(wildcard include/config/HAVE_PERF_REGS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/uapi/asm/perf_regs.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cgroup.h \
    $(wildcard include/config/DEBUG_CGROUP_REF) \
    $(wildcard include/config/CGROUP_CPUACCT) \
    $(wildcard include/config/SOCK_CGROUP_DATA) \
    $(wildcard include/config/CGROUP_DATA) \
    $(wildcard include/config/CGROUP_BPF) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/cgroupstats.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/taskstats.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/user_namespace.h \
    $(wildcard include/config/INOTIFY_USER) \
    $(wildcard include/config/FANOTIFY) \
    $(wildcard include/config/BINFMT_MISC) \
    $(wildcard include/config/PERSISTENT_KEYRINGS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kernel_stat.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cgroup-defs.h \
    $(wildcard include/config/CGROUP_NET_CLASSID) \
    $(wildcard include/config/CGROUP_NET_PRIO) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/u64_stats_sync.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bpf-cgroup-defs.h \
    $(wildcard include/config/BPF_LSM) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/psi_types.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kthread.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cgroup_subsys.h \
    $(wildcard include/config/CGROUP_DEVICE) \
    $(wildcard include/config/CGROUP_FREEZER) \
    $(wildcard include/config/CGROUP_HUGETLB) \
    $(wildcard include/config/CGROUP_PIDS) \
    $(wildcard include/config/CGROUP_RDMA) \
    $(wildcard include/config/CGROUP_MISC) \
    $(wildcard include/config/CGROUP_DMEM) \
    $(wildcard include/config/CGROUP_DEBUG) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cgroup_refcnt.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/security.h \
    $(wildcard include/config/SECURITY_NETWORK) \
    $(wildcard include/config/SECURITY_INFINIBAND) \
    $(wildcard include/config/SECURITY_NETWORK_XFRM) \
    $(wildcard include/config/SECURITY_PATH) \
    $(wildcard include/config/SECURITYFS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kernel_read_file.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/file.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/sockptr.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bpf.h \
    $(wildcard include/config/FINEIBT) \
    $(wildcard include/config/BPF_JIT_ALWAYS_ON) \
    $(wildcard include/config/INET) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/bpf.h \
    $(wildcard include/config/BPF_LIRC_MODE2) \
    $(wildcard include/config/EFFICIENT_UNALIGNED_ACCESS) \
    $(wildcard include/config/IP_ROUTE_CLASSID) \
    $(wildcard include/config/BPF_KPROBE_OVERRIDE) \
    $(wildcard include/config/XFRM) \
    $(wildcard include/config/IPV6) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/bpf_common.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/filter.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bpfptr.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/btf.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bsearch.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/btf_ids.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/btf.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/memcontrol.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/page_counter.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/vmpressure.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/eventfd.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/eventfd.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/writeback.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/flex_proportions.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/backing-dev-defs.h \
    $(wildcard include/config/DEBUG_FS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/blk_types.h \
    $(wildcard include/config/FAIL_MAKE_REQUEST) \
    $(wildcard include/config/BLK_CGROUP_IOCOST) \
    $(wildcard include/config/BLK_INLINE_ENCRYPTION) \
    $(wildcard include/config/BLK_DEV_INTEGRITY) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bvec.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/highmem.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cacheflush.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/cacheflush.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kgdb.h \
    $(wildcard include/config/HAVE_ARCH_KGDB) \
    $(wildcard include/config/KGDB) \
    $(wildcard include/config/SERIAL_KGDB_NMI) \
    $(wildcard include/config/KGDB_HONOUR_BLOCKLIST) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kprobes.h \
    $(wildcard include/config/KRETPROBE_ON_RETHOOK) \
    $(wildcard include/config/OPTPROBES) \
    $(wildcard include/config/KPROBES_ON_FTRACE) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/objpool.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/rethook.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/kprobes.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/kprobes.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/kgdb.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/asm/debug-monitors.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/cacheflush.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/kmsan.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/dma-direction.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/highmem-internal.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/pagevec.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bio.h \
    $(wildcard include/config/BLK_DEV_ZONED) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/mempool.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/cfi.h \
    $(wildcard include/config/CFI_CLANG) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/arch/arm64/include/generated/asm/cfi.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/asm-generic/cfi.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/bpf_types.h \
    $(wildcard include/config/NETFILTER_BPF_LINK) \
    $(wildcard include/config/XDP_SOCKETS) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/uapi/linux/lsm.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/lsm/selinux.h \
    $(wildcard include/config/SECURITY_SELINUX) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/lsm/smack.h \
    $(wildcard include/config/SECURITY_SMACK) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/lsm/apparmor.h \
    $(wildcard include/config/SECURITY_APPARMOR) \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/lsm/bpf.h \
  /home/jermaineb/EDR-platform/edr-agent/src/asahi-kernel-exact/include/linux/proc_fs.h \
    $(wildcard include/config/PROC_PID_ARCH_STATUS) \

lkm.o: $(deps_lkm.o)

$(deps_lkm.o):
