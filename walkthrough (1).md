# Walkthrough: Note Service Exploitation

We successfully exploited the Note-taking service ("Classy who?") to read the flag from stack memory.

## 1. Vulnerability & Exploit Tactics
- **Heap Overflow**: [write_note](file:///c:/Users/Gugan/Downloads/ctf/ctf.c#82-103) matches missing bounds check on `offset + len`. We overwrite an adjacent note's metadata struct (`note 3`).
- **Use-After-Free**: [delete_note](file:///c:/Users/Gugan/Downloads/ctf/ctf.c#123-138) does not nullify ptr. Re-allocating the same size pulls the chunk from the unsorted bin containing stale libc pointers.
- **Arbitrary Memory Read**: Overwriting `notes[3]->data` with a target address allows reading arbitary memory values. We used this to brute-force candidate stack pointer `__environ` offsets in the libc `.data` section, then scanned the stack segment downward to read the flag.

## 2. Exploitation Steps
1. **Unsorted Bin Leak**: Allocate `note 0` (0x8), `note 1` (0x500), `note 2` (guard). Free `note 1` to place its data chunk in the unsorted bin, then allocate `note 3` (0x500) to retrieve it, leaking a libc address from `bk`/`fd`.
2. **Brute Force Stack Pointer**: Overwrite `note 3` struct with potential `__environ` addresses. We identified `__environ` at base offset `0x101370`, leaking stack address `0x7ffe8bb8ad13`.
3. **Optimized Scan**: Scan memory ranges downward from leaked stack address using exact-size reads (`recvn`) to bypass formatting conflicts.

## 3. Findings
- **Target**: `13.206.57.188:10024`
- **Flag**: `athena{367ziRCKfCPebdSb}`
