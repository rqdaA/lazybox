ENTRY(_start)
SECTIONS
{
    . = 0x400c0;  /* 開始アドレス */
    .text : {
        *(.text*)
        *(.rodata*)
        *(.data*)
        *(.bss*)
    }
    /DISCARD/ : {
        *(.note*)
        *(.comment*)
        *(.eh_frame*)
        *(.gnu.hash*)
        *(.hash*)
        *(.dynsym*)
        *(.dynstr*)
        *(.gnu.version*)
    }
}
