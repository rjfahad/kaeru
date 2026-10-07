//
// SPDX-FileCopyrightText: 2026
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <board_ops.h>

void board_early_init(void) {
    printf("Entering early init for realme RUI2\n");

    // get_sboot_state (0x4c467d3c) reads the seccfg sboot state with
    // `bl 0x4c467c6c` and stores the result into the caller's buffer; the
    // cmdline builder appends "androidboot.sbootstate=on" only when that
    // state is 1. Replace the getter call with `movs r0,#1; nop` so the
    // stored state is always 1 (on) for every caller.
    PATCH_MEM(0x4c467d42, 0x2001, 0xBF00);
    printf("get_sboot_state Patched\n");

    // fastboot_init publishes the getvar values from two helpers:
    //   secure   <- 0x4c469060 -> force 1 (yes)
    //   unlocked <- 0x4c4690b0 -> force 0 (no)
    // 0x4c4690b0 is also consulted by the fastboot gates below, but their
    // deny branches are NOP'd, so forcing it is safe.
    FORCE_RETURN(0x4c469060, 1);
    FORCE_RETURN(0x4c4690b0, 0);
    printf("fastboot getvar Patched\n");

    // androidboot.verifiedbootstate= is written into the kernel cmdline by
    // the dispatcher at 0x4c442b0c: it reads the boot-state global and
    // dispatches via tbb (table @0x4c442b1e: 14 02 0e 08) to append "green"
    // (0, 0x4c442b46), "yellow", "orange" or "red". Force the dispatch index
    // to 0 so the append always uses the green case:
    //   patch 0x4c442b16  cmp r3,#0x3  ->  movs r3,#0x0  (0x2300)
    //   NOP   0x4c442b18  bhi (bounds check, now harmless)
    PATCH_MEM(0x4c442b16, 0x2300);
    NOP(0x4c442b18, 1);
    printf("verified_boot_state Patched\n");

    // fastboot command dispatch runs two per-command security gates that
    // deny execution depending on the (spoofed) lock state. NOP the four
    // deny branches (FAIL handler is 0x4c4253a0) so every command passes:
    //   gate 1: deny if [r7,#0xc]==0 (0x4c4254a4), deny if lock-check 0 (0x4c4254ae)
    //   gate 2: same two checks (0x4c4254d2, 0x4c4254dc)
    NOP(0x4c4254a4, 1);
    NOP(0x4c4254ae, 1);
    NOP(0x4c4254d2, 1);
    NOP(0x4c4254dc, 1);
    printf("fastboot_handler Patched\n");

    // Security policy extractors over the SEC_POLICY table (getter
    // 0x4c415498): 0x4c4155a8 = (val & 3) >> 1 (dl_policy) and
    // 0x4c4155b4 = val & 1 (vfy_policy). Forcing both to 0 skips
    // verification/auth and removes flash restrictions.
    FORCE_RETURN(0x4c4155a8, 0);
    FORCE_RETURN(0x4c4155b4, 0);
    printf("policy Patched\n");

    // avb device_state append: the string selection does
    // `ldr r3,[sp,#0x1c]; cbnz -> "unlocked"` at 0x4c4532de (else "locked"
    // at 0x4c4532e0). NOP the branch so avb always appends device_state=locked.
    NOP(0x4c4532de, 1);
    printf("avb device_state Patched\n");

    // Orange State unlock warning (fn 0x4c44299c): prints "Orange State /
    // Your device has been unlocked and can't be trusted / ... boot in 5
    // seconds", sleeps 5000ms, returns 0. Reached via `b.w` from 0x4c442ae4
    // when the boot-state global is orange. Force return 0 to drop both the
    // screen and the delay.
    FORCE_RETURN(0x4c44299c, 0);
    printf("orange_state_warning Patched\n");

    // dm-verity corruption screen (fn 0x4c458e5e): prints "dm-verity
    // corruption / Your device is corrupt.". Reached via `beq` from
    // 0x4c458e5a. Visual only - force return 0.
    FORCE_RETURN(0x4c458e5e, 0);
    printf("dm_verity_corruption Patched\n");
}

void board_late_init(void) {
    printf("Entering late init for realme RUI2\n");
}
