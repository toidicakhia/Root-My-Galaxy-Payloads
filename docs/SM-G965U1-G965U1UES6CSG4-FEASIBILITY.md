# SM-G965U1 / G965U1UES6CSG4 — Linux 4.9 feasibility report

Status: **research only**. This is not a supported target, is not in
`support/targets-v3.json`, and must not be published as an app payload without
device validation. The complete `G965U1UES6CSG4` firmware has been verified
statically (boot/Image hashes, XBL kernel region, SELinux/seccomp policy, and
the 4.9 virtual layout), but nothing has run on a physical device. The
implemented 4.9 port, including the legacy configfs path and the PTRACE stack
writer, is described in `docs/SM-G965U1-G965U1UES6CSG4-PORT-NOTES.md`.

## 1. Identity

`Files.rar` is a partial extract (`boot.img` and `xbl_config.elf`). The
complete `SAMFW.COM_SM-G965U1_XAA_G965U1UES6CSG4_fac.zip` was obtained and
verified; it is not an `SM-G695U1` firmware:

| Field | Value |
| --- | --- |
| Model | `SM-G965U1` (Galaxy S9+, US unlocked) |
| Codename | `star2qlteue` |
| SoC | Qualcomm Snapdragon 845 (`sdm845`) |
| Android | 9 (SDK 28) |
| Firmware | `G965U1UES6CSG4` |
| Kernel | `4.9.112-16002534` |
| Kernel build | `Wed Jul 17 10:49:42 KST 2019` |
| Boot header | Android boot image v0, 4096-byte pages |
| Kernel `text_offset` | `0x00080000` |
| Kernel `image_size` | `0x033fb000` |
| Image flags | `0xa` (little-endian, 4K pages) |

Evidence:

- `xbl_config.elf` contains `SM-G965U1_NA_XAA_USA`.
- `system/build.prop` contains
  `ro.build.fingerprint=samsung/star2qlteue/star2qlteue:9/PPR1.180610.011/G965U1UES6CSG4:user/release-keys`.
- The kernel version string is `Linux version 4.9.112-16002534`.
- The kernel build date matches the `G965U1UES6CSG4` release date.
- The kernel contains the `star2`/`G965` platform strings.
- XBL reserves `0x80000000` + `0x05700000` as the `"Kernel"` region, and
  the next region is `hyp_region@85700000` (6 MiB).

Provenance hashes:

```text
archive     70afd520965791a6a675194eca7c6053c50f88628c194ca03abf24ca72a4f1d5
AP tar      8dbeded47f79d46f748c981f433c3a7d2f0f18dedb57eb42759b7bfac4e010bb
boot.img    13917457dff7650317ec8e48e5c9385f9c8e014696e5b937868042fa3a0a21df
kernel.gz   53080f2ae62708f0370a640fcf3dfe9aeca7c8338508f9606281278c9cb16905
Image       57fb5a20900ec4481e32883ded6e25236442699c8722ac4b60acaf297d84eb36
```

The AP tar inside the archive is byte-identical to the extracted
`AP_G965U1UES6CSG4_...tar.md5`. Its `boot.img.lz4` decompresses to the
same `boot.img` as `Files.rar`, and the gzip kernel payload decompresses to
the same `Image` used for the offset work. The build identity is therefore
confirmed from the firmware, not inferred from the build date.

The firmware also resolves the virtual memory layout: the image's
`address_markers` table gives `PAGE_OFFSET = 0xffffffc000000000` and
`VMEMMAP_START = 0xffffffbf00000000`. The earlier 5.x-style assumption
(`0xffffff8000000000` / `0xffffff7f00000000`) was wrong for 4.9 and has
been corrected in the target and the rebuilt payloads.

## 2. CVE applicability

CVE-2026-43499 affects Linux `2.6.39` through `6.1.174`; `4.9.112` is inside
that range. The vulnerable pattern is present in the 4.9 source:
`remove_waiter()` uses `current` instead of `waiter->task` for the proxy-lock
rollback path.

The 4.9 kernel also provides the primitives used by the PoC:

- `FUTEX_WAIT_REQUEUE_PI`, `FUTEX_CMP_REQUEUE_PI`, and PI futex support;
- `sched_setattr` (`SCHED_BATCH`, nice 19);
- `pselect6` and `core_sys_select`;
- `ashmem`, `configfs`, pipes, `memfd`, and tracefs;
- `sched:sched_blocked_reason` for the KASLR leak.

So the **bug is applicable**. The open question is not the CVE, but whether the
existing exploit implementation can be adapted to the 4.9 ABI and whether
Samsung RKP/KDP/DEFEX permit the required writes.

## 3. Hard blockers and porting work

### 3.1 KernelSU is not viable on this kernel

`4.9.112` cannot run the KernelSU v3.2.5 late-load path used by this
repository:

| Requirement | 4.9.112 status |
| --- | --- |
| `CONFIG_KPROBES` | absent |
| `CONFIG_FUNCTION_TRACER` / `CONFIG_DYNAMIC_FTRACE` | absent |
| `CONFIG_MODULE_SIG_FORCE` | `y` — unsigned modules rejected |
| KernelSU minimum kernel | 5.10+ GKI |
| `CONFIG_MODVERSIONS` | `y` |

The only plausible root route is the standalone `su` daemon
(`artifacts/*/cve-2026-43499-root`) loaded through the
`call_usermodehelper_exec_work` path. That is a shell/root-helper profile, not
an app-feed KernelSU profile. It would be analogous to the experimental
`dm2q-S916BXXSAFZG1` shell-only port, not to the 5.10/6.1 targets.

### 3.2 Samsung protections are unresolved

The image contains the expected protection code:

```text
rkp_init, rkp_override_creds, rkp_assign_pgd, rkp_pgt_bitmap_arr
defex_syscall_enter, task_defex_enforce, defex_get_features
five_ptrace, five_bprm_check, five_file_verify
```

The DTB reserves `rkp_region@9FA00000` (15 MiB). `rkp_init` calls
`uh_call` and sets an enable flag, and `defex_get_features` returns `0x81`
(features 0 and 7 enabled). DEFEX can zero credentials and send SIGKILL on
a detected privilege escalation. RKP/KDP may reject writes to credentials,
`selinux_enforcing`, page tables, or kernel text. The newer Samsung targets
in this repository handle these mechanisms in the KernelSU patch and in the
physical read/write stage; none of that work is known to transfer to the
4.9 RKP implementation. This is the highest-risk part of the port and
requires hardware testing.

The static firmware checks also narrow the problem:

| Check | Result |
| --- | --- |
| `plat_sepolicy.cil:15442` | `(allow untrusted_app_all self (process (ptrace)))` |
| Vendor policy | does not remove the `ptrace` allow rule |
| `libandroid_runtime.so` `arm64_app_filter` | 57 entries; syscall 117 (`ptrace`) reaches `SECCOMP_RET_ALLOW` |
| Yama symbols | no `yama_ptrace_access_check` / `ptrace_scope`; probably absent |
| `five_ptrace` request `0x4205` | takes the audit path (`"ptrace"`/`"reset-integrity"`) and returns 0; does not block |
| `five_bprm_check` / `five_file_verify` | present; the unsigned UMH helper may be verified at exec |
| Boot cmdline | `androidboot.selinux=permissive` |
| Build type | `ro.build.type=user`, `ro.build.selinux=1` |

The `androidboot.selinux=permissive` cmdline is ambiguous. AOSP 9 user
builds define `ALLOW_PERMISSIVE_SELINUX` as false and ignore it, and Samsung
init additionally references `ro.build.selinux.enforce` (unset in the
extracted properties). `getenforce` on the device is authoritative. The
`ptrace` allow rule and seccomp result are favorable for the PTRACE stack
writer, but RKP/DEFEX/FIVE still make the root stage unproven.

### 3.3 The existing exploit assumes 5.x layouts

The current target headers are written for 5.10/5.15/6.1/6.6. The following
values are **different** on 4.9 and cannot be copied:

| Item | 5.x assumption | 4.9 reality |
| --- | --- | --- |
| `struct file_operations.unlocked_ioctl` | `0x50` | `0x48` |
| `struct file_operations.compat_ioctl` | `0x58` | `0x50` |
| `struct file_operations.mmap` | `0x60` | `0x58` |
| `struct file_operations.open` | `0x70` | `0x60` |
| `struct file_operations.release` | `0x80` | `0x70` |
| `struct file_operations.splice_read` | `0xc8` | `0xb8` |
| `struct file_operations.show_fdinfo` | `0xe0` | `0xd0` |
| `struct page.compound_head` | `0x08` | `0x20` |
| `struct page.slab_cache` | `0x18` | `0x30` |
| `struct page.page_type` | `0x30` | field does not exist |
| `configfs_read_iter` / `configfs_bin_write_iter` | present | **absent** |
| `selinux_state.enforcing` | struct field | global `selinux_enforcing` |
| `ashmem_show_fdinfo` | present | **absent** |
| linear map / `P0_PAGE_OFFSET` | `0xffffff8000000000` | `0xffffffc000000000` |
| `VMEMMAP_START` | `0xffffff7f00000000` | `0xffffffbf00000000` |

The virtual-layout row is not a guess: the image's `address_markers` table
contains the 4.9 boundaries (`PAGE_OFFSET = 0xffffffc000000000`,
`VMEMMAP_START = 0xffffffbf00000000`, linear map end
`0xffffffffffffffff`). The 5.x-style constants that were initially copied
into this profile were wrong and made every direct-map alias point into the
modules/vmalloc region. They are now corrected in `target.h` and the
payloads are rebuilt.

The 4.9 `struct file_operations` layout is:

```text
owner            0x00
llseek           0x08
read             0x10
write            0x18
read_iter        0x20
write_iter       0x28
iterate          0x30
iterate_shared   0x38
poll             0x40
unlocked_ioctl   0x48
compat_ioctl     0x50
mmap             0x58
open             0x60
flush            0x68
release          0x70
fsync            0x78
fasync           0x80
lock             0x88
sendpage         0x90
get_unmapped_area 0x98
check_flags      0xa0
flock            0xa8
splice_write     0xb0
splice_read      0xb8
setlease         0xc0
fallocate        0xc8
show_fdinfo      0xd0
copy_file_range  0xd8
```

The 4.9 `struct rt_mutex_waiter` is the legacy shape:

```text
tree_entry      0x00
pi_tree_entry   0x18
task            0x30
lock            0x38
prio            0x40
deadline        0x48
size            0x50
```

There is no `wake_state` or `ww_ctx`, but this Samsung build does have the
`deadline` qword at `0x48`: `task_blocks_on_rt_mutex` executes
`ldr x0, [task, #0x4c8]; str x0, [waiter, #0x48]`. The repository's
`LEGACY_RT_MUTEX_WAITER` path is therefore the correct match, and
`FAKE_WAITER_DEADLINE_OFF 0x48` is inside the 0x50-byte object.

### 3.4 Legacy configfs read/write path (implemented)

4.9 has no `configfs_read_iter` or `configfs_bin_write_iter`. It uses the
older `.read`/`.write` callbacks:

```text
configfs_read_file       0x2659f8
configfs_write_file      0x265fa8
configfs_read_bin_file   0x265af8
configfs_write_bin_file  0x265c38
```

`configfs_write_bin_file` exists, but its `configfs_buffer`/`config_item`
lookup goes through the real `file->f_path.dentry` and inode. An ashmem file's
dentry is not a configfs dentry, so the fake object cannot steer that path.
The port uses the classic callbacks instead.

The fake fops table uses offsets `0x10`/`0x18` and points:

```text
llseek  noop_llseek
read    configfs_read_file
write   configfs_write_file
```

`configfs_read_file` with `needs_read_fill = 0` and `page` pointing near the
target calls `simple_read_from_buffer()`, which gives arbitrary read.
`configfs_write_file` copies the user buffer into `buffer->page`, and only
then dereferences the real dentry. If the source faults, it returns `-EFAULT`
before that dereference, so the bytes copied before the fault remain at the
target. The fault path also writes `buffer->page[count] = 0`, so every
successful range leaves **two zero bytes** immediately after it. The port
writes 64-byte chunks and verifies each one with `configfs_read_once()`.

The two zero bytes required two restore changes:

- `miscdevice` is restored as a snapshot of `0x10..0x49`, with the collateral
  falling into the `0x4a..0x4b` tail padding before `ashmem_shrinker`;
- the `random_table` boot_id entry is restored as a 0x18-byte `ctl_table`
  snapshot after verifying `child == NULL`, so the collateral lands in the low
  two bytes of the already-NULL child pointer.

Every other write call site still has to be audited against this rule on
hardware. See `docs/SM-G965U1-G965U1UES6CSG4-PORT-NOTES.md` section 3.4.

### 3.5 4.9 stack writer: PTRACE_SETREGSET (implemented)

The pselect writer cannot reach the 4.9 waiter. The relevant frames are:

```text
sys_futex frame                     0x80
do_futex frame                      0x130
futex_wait_requeue_pi frame         0x1c0
  real rt_mutex_waiter              x29+0x90  = entry_sp-0x2e0
  on-stack struct futex_q           x29+0x148 = entry_sp-0x228
sys_pselect6 frame                  0xa0
core_sys_select frame               0x1b0, fd_set storage at +0xa8
```

An earlier draft mistook the `futex_q` for the waiter. The
`rt_mutex_finish_proxy_lock` call site at `0xffffff800815cb70` passes
`x2 = x29+0x90`, which is the real 0x50-byte waiter.

The deep-write alternatives were checked and rejected:

- 64-bit ashmem `SET_NAME` reaches `entry_sp-0x298` (`waiter+0x48`), so it
  only overwrites `deadline`;
- the compat ashmem path reaches `entry_sp-0x2e8`, but it is 32-bit-only and
  is a NUL-terminated `strncpy_from_user`, so it cannot carry zero bytes;
- native 64-bit WEXT/route ioctls do not reach this depth; the deeper
  `compat_wext_handle_ioctl` is 32-bit-only.

The selected writer is `PTRACE_SETREGSET` with `NT_PRFPREG`:

```text
sys_ptrace          0x40
arch_ptrace         0x10
ptrace_request      0xe0
ptrace_regset       0x40
fpr_set             0x280
```

`fpr_set` therefore has `x29 = entry_sp-0x3f0`. Its 0x210-byte FPSIMD buffer
is at `x29+0x60 = entry_sp-0x390`, and the stale waiter begins at buffer
offset `0xb0`. `ptrace_regset` passes `pos=0`, `count=iov.len=0x210`,
`kbuf=NULL`, and `ubuf=iov.base`; the length check passes because
`0x210 % 4 == 0`. The full waiter is overwritten.

The app profile prepares a stopped child before the futex wait with
`clone(SIGCHLD)` + `PTRACE_TRACEME` + `tgkill(SIGSTOP)` + `waitpid`. After the
futex path and the writer's ptrace call, the waiter thread sets
`slide_consume_go` and spins without making any further syscall until the
consumer's `sched_setattr()` has walked the PI chain. A syscall there would
reuse the same kernel stack and overwrite the fake waiter.

### 3.6 Physical slide and P0 fingerprint (generated, unverified)

The ARM64 Image has `text_offset = 0x80000`, so the working assumption is:

```c
#define P0_PHYS_OFFSET       0x80000000ULL
#define P0_KERNEL_PHYS_LOAD  0x80080000ULL
```

`src/targets/star2qlteue-G965U1UES6CSG4/p0_fingerprint.h` now exists. It was
generated from the raw `Image` at probe offset `0x1f0000`: 32 candidate
slides (0x000000..0x1f0000 in 64 KiB steps), 8 qwords per slide, 256 qwords
total. The table is still only as good as the physical load assumption.
XBL reserves `0x80000000` + `0x05700000` as the `"Kernel"` region, so the
region base is confirmed, but the 64 KiB-step placement range is not.

`VMEMMAP_START = 0xffffffbf00000000` is now derived from the image's
`address_markers` table (`PAGE_OFFSET = 0xffffffc000000000`,
`VMEMMAP_SIZE = 4 GiB`), not inherited from 5.x. `SKB_DATA_DELTA = -0xe80`
is still inherited and uncalibrated for 4.9. Confirm the physical placement,
the SKB geometry, and the slab order on hardware before trusting the P0
path.

The 4.9 KASLR code also derives `memstart_offset_seed` from the top 16 bits
of the same `kaslr-seed` and uses it to lower `memstart_addr` (and therefore
`PHYS_OFFSET`). The P0 alias model assumes `memstart_addr == 0x80000000`; a
full 64-bit seed would shift every direct-map alias and make the P0 oracle
read the wrong physical page. The port currently fails closed on the
fingerprint/alias checks instead of leaking `memstart_addr`.

No BL/AP boot component contains the literal `kaslr-seed`, and the static
DTB has no such property, so the expected seed is zero. The slide then comes
from the bootloader's physical misalignment: `stext` loads
`x23 = __PHYS_OFFSET & (SZ_2M - 1)`, and `__create_page_tables` adds `x23`
to `KIMAGE_VADDR + TEXT_OFFSET`. For the 64 KiB-granular placements covered
by the 32-row P0 table, physical and virtual text therefore move together.
A 2 MiB-aligned placement beyond the first 2 MiB (`x23 == 0`) or an injected
seed would break that equality; the port would then need separate physical
and virtual bases.

## 4. Values that are already derived

The kernel was reconstructed with `vmlinux-to-elf` at the unslid base
`0xffffff8008080000` (39-bit VA, `KIMAGE_VADDR = 0xffffff8008000000`,
`text_offset = 0x80000`). Selected symbol offsets:

| Symbol | Offset from `_text` |
| --- | ---: |
| `call_usermodehelper_exec_work` | `0x00048c5c` |
| `worker_thread` | `0x0004c880` |
| `noop_llseek` | `0x001d0e30` |
| `generic_file_splice_read` | `0x0020ab6c` |
| `configfs_read_file` | `0x002659f8` |
| `configfs_read_bin_file` | `0x00265af8` |
| `configfs_write_bin_file` | `0x00265c38` |
| `configfs_write_file` | `0x00265fa8` |
| `ashmem_open` | `0x00dbc338` |
| `ashmem_mmap` | `0x00dbc3c8` |
| `ashmem_ioctl` | `0x00dbc9e4` |
| `compat_ashmem_ioctl` | `0x00dbd004` |
| `ashmem_release` | `0x00dbd064` |
| `anon_pipe_buf_ops` | `0x0169fe80` |
| `ashmem_fops` | `0x018157e0` |
| `init_task` | `0x029a7800` |
| `system_unbound_wq` | `0x02994780` |
| `nfulnl_logger` | `0x0299d480` |
| `root_task_group` | `0x02c62580` |
| `kmalloc_caches` | `0x02cf1778` |
| `selinux_enforcing` | `0x015e00f0` |
| `init_cred` | `0x015e0008` |
| `commit_creds` | `0x00056ff4` |
| `prepare_kernel_cred` | `0x00057728` |
| `core_sys_select` | `0x001ea18c` |
| `sys_pselect6` | `0x001ea72c` |
| `sys_futex` | `0x000de88c` |
| `do_futex` | `0x000de05c` |
| `futex_wait_requeue_pi.constprop.19` | `0x000dc834` |
| `futex_requeue` | `0x000dce0c` |
| `rt_mutex_adjust_prio_chain` | `0x000a4438` |
| `rt_mutex_start_proxy_lock` | `0x000a4f40` |
| `rt_mutex_finish_proxy_lock` | `0x000a5028` |
| `sys_ptrace` | `0x0003b8a0` |
| `arch_ptrace` | `0x000091a8` |
| `ptrace_request` | `0x0003babc` |
| `ptrace_regset` | `0x0003a4f4` |
| `fpr_set` | `0x000077f8` |

The static `sys_call_table` reads as zero because its entries are
`R_AARCH64_RELATIVE` relocations applied at boot. The Image relocation entries
resolve `table[117]` to `sys_ptrace`, `table[98]` to `sys_futex`, and
`table[220]` to `sys_clone`, confirming that `el0_svc` calls those functions
directly with `sp` at the syscall entry frame.

KASLR leak values:

```c
#define SLIDE_TRACEFS_EVENT_ID          71
#define SLIDE_TRACEFS_WORKER_CALLER_OFF 0x0004ca4cULL
```

The event is at index 54 in the `__start_ftrace_events` array; 4.9 starts
dynamic event IDs at `__TRACE_LAST_TYPE + 1` (`17`), so the derived ID is
`71`. Confirm it on the device with:

```sh
cat /sys/kernel/debug/tracing/events/sched/sched_blocked_reason/id
```

The `worker_thread` return PC is `0xffffff80080cca4c`, which gives the
`0x4ca4c` offset. Verify that observed kworker callers are 64-KiB aligned
before accepting it.

The `nfulnl_logger` object is at `0x0299d480`; its `name` field points at the
`"nfnetlink_log"` string at `0x021d82e0`. The 4.9 `struct nf_logger` starts
with `char *name`, so the existing first-qword leak model still applies.

## 5. Verdict

| Question | Answer |
| --- | --- |
| Is CVE-2026-43499 present? | **Yes** (4.9.112 < 6.1.175) |
| Has the payload been checked against the full firmware? | **Yes** — boot/Image hashes, XBL kernel region, PTrace policy, seccomp, and layout constants |
| Can the current app payload be built for it? | **Yes** — debug `.so` and 104,128-byte release `.so` |
| Are the direct-map constants correct? | **Yes** — corrected to `0xffffffc000000000` / `0xffffffbf00000000` from `address_markers` |
| Has it been validated on a physical device? | **No** |
| Can a standalone root-helper port work? | **Plausible, unproven** — RKP/DEFEX/FIVE and the 4.9 workqueue offsets are unresolved |
| Can KernelSU late-load work? | **No** |
| Is it a `target.h`-only change? | **No** — it is a multi-stage ABI port |
| Should it be added to the public feed now? | **No** |

The port now contains:

1. a 4.9 target profile with `file_operations`, `struct page`,
   `configfs_buffer`, `rt_mutex_waiter`, and `task_struct` layouts;
2. the legacy `configfs_read_file`/`configfs_write_file` fake fops and the
   fault-based two-byte-collateral write primitive;
3. corrected waiter geometry and the `PTRACE_SETREGSET`/`NT_PRFPREG` stack
   writer;
4. a generated P0 fingerprint at probe offset `0x1f0000`;
5. the 4.9 virtual layout recovered from the image (`PAGE_OFFSET =
   0xffffffc000000000`, `VMEMMAP_START = 0xffffffbf00000000`);
6. debug and release app builds with NDK r29, rebuilt after the layout
   correction.

Remaining work is device validation:

1. obtain a sacrificial `SM-G965U1` with an Odin recovery path;
2. confirm the exact physical load placement, the absence of a
   `kaslr-seed`/`memstart_addr` shift, and the P0 range from the boot log /
   `/proc/iomem`;
3. verify `mm_struct` slab order, tracefs event ID, Yama, the runtime SELinux
   state, and the installed seccomp filter;
4. validate the KASLR leak in isolation (`SLIDE_ONLY=1`), then the UAF crash,
   then the PTRACE stack writer and arbitrary read/write;
5. audit every remaining `configfs_write_once()` call site for the two-byte
   collateral;
6. re-derive the 4.9 workqueue offsets, then attempt the
   `call_usermodehelper` root helper under FIVE/RKP/DEFEX;
7. only after hardware validation consider a shell-only app profile.

KernelSU and the normal `support/targets-v3.json` feed are out of scope for
this kernel.

## 6. Inputs still required

From the device (or a complete firmware package):

```sh
getprop ro.product.model
getprop ro.build.fingerprint
getprop ro.build.display.id
getprop ro.boot.bootloader
getprop ro.boot.flash.locked
getprop ro.boot.verifiedbootstate
getprop ro.boot.warranty_bit
getprop ro.csc.sales_code
uname -a
cat /proc/version
```

The full firmware is no longer an input: `SAMFW.COM_SM-G965U1_XAA_G965U1UES6CSG4_fac.zip`
has been verified. The remaining input is a sacrificial `SM-G965U1` with an
Odin recovery path and the matching AP/BL/CSC/CP files for restore.

Runtime checks to perform before trusting the port:

```sh
getprop ro.boot.selinux
getprop ro.build.selinux.enforce
getenforce
cat /sys/fs/selinux/enforce
cat /sys/kernel/slab/mm_struct/order
cat /sys/kernel/debug/tracing/events/sched/sched_blocked_reason/id
cat /proc/sys/kernel/yama/ptrace_scope
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/iomem | grep -i kernel
dmesg | grep -A12 'Virtual kernel memory layout'
```

The boot log should show the linear map at `0xffffffc000000000` and the
vmemmap at `0xffffffbf00000000`. If it does not, stop: the target layout is
wrong for that boot. Also check `dmesg` for RKP/DEFEX/FIVE messages while
running the first stages.

Without the device, the binaries built from this profile are research
artifacts only. Publishing them now would be an unvalidated guess and could
bootloop the device.
