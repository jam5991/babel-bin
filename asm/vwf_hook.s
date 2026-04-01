# ─────────────────────────────────────────────────────────────
# Variable Width Font (VWF) Hook for MIPS R3000A (PS1)
# ─────────────────────────────────────────────────────────────
# This hook intercepts the game's original fixed-width text rendering call,
# loads an ASCII character, looks up its proportional width from a table,
# and advances the cursor dynamically instead of by a fixed 16x16 amount.
#
# Assemble with:
#   mips-linux-gnu-as -EL -mips1 vwf_hook.s -o vwf_hook.o
#   mips-linux-gnu-objcopy -O binary vwf_hook.o vwf_hook.bin

.set noreorder
.set noat
.set mips1

# --- Constants & Offsets ---
# These would typically be patched by the Injector dynamically,
# but for the template we use placeholder addresses.

# Address of the ASCII width table (256 bytes)
WIDTH_TABLE_ADDR = 0x8001F000

# Original rendering function that prints one character
ORIGINAL_RENDER_SUBROUTINE = 0x80014B20

# Assume $a0 contains the character code, and $a1 contains the cursor X coordinate.
# Return the updated X coordinate in $v0.

.text
.globl vwf_entry

vwf_entry:
    # Prologue: save registers we're going to use
    addiu   $sp, $sp, -24
    sw      $ra, 20($sp)
    sw      $s0, 16($sp)
    sw      $s1, 12($sp)

    # Save original arguments
    move    $s0, $a0        # $s0 = char code
    move    $s1, $a1        # $s1 = current X coord

    # Call original rendering subroutine (fixed 16x16 render)
    jal     ORIGINAL_RENDER_SUBROUTINE
    nop                     # Branch delay slot

    # Lookup character width dynamically
    lui     $t0, %hi(WIDTH_TABLE_ADDR)
    addiu   $t0, $t0, %lo(WIDTH_TABLE_ADDR)

    # Width table offset = Base + CharCode
    addu    $t1, $t0, $s0

    # Load the width byte for this character
    lbu     $t2, 0($t1)

    # Default to 16 if width is 0 (fallback)
    bne     $t2, $zero, width_ok
    nop
    li      $t2, 16

width_ok:
    # Update cursor X coordinate
    addu    $v0, $s1, $t2

    # Epilogue: restore registers and return
    lw      $s1, 12($sp)
    lw      $s0, 16($sp)
    lw      $ra, 20($sp)
    jr      $ra
    addiu   $sp, $sp, 24    # Branch delay slot: restore Stack Pointer

