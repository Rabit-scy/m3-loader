#include "sta_mem_map.h"

MEMORY
{
  ESRAM_M3 (wx)                   : ORIGIN = 0x10000000,  LENGTH = ESRAM_M3_SIZE
  ESRAM_AP (wx)                   : ORIGIN = ESRAM_A7_BASE,  LENGTH = ESRAM_A7_SIZE
  DRAM (wx)                       : ORIGIN = DDRAM_BASE,  LENGTH = DDRAM_SIZE
}

ENTRY(reset_handler)

SECTIONS
{
  __ESRAM_M3_start     = ORIGIN(ESRAM_M3);
  __ESRAM_M3_end       = ORIGIN(ESRAM_M3) + LENGTH(ESRAM_M3);
  __ESRAM_AP_start     = ORIGIN(ESRAM_AP);
  __ESRAM_AP_end       = ORIGIN(ESRAM_AP) + LENGTH(ESRAM_AP);
  __DRAM_start         = ORIGIN(DRAM);

   /* The 128 last ESRAM AP bytes are reserved for M3/AP shared data */
  __ESRAM_AP_segment_end__  = ESRAM_A7_SHARED_DATA_BASE;

  __MBOX_OFFSET__ = (ESRAM_A7_APP_OS_MAILBOXES_BASE - ESRAM_A7_BASE);
  __MBOX_SIZE__ = ESRAM_A7_APP_OS_MAILBOXES_SIZE;
#ifdef ATF
  __MBOX_SEC_OFFSET__ = (ESRAM_A7_ATF_IPC_BASE - ESRAM_A7_ATF_TRUSTED_ZONE_BASE);
  __MBOX_SEC_SIZE__ = ESRAM_A7_ATF_IPC_SIZE;
#endif

  __MAX_XLF_SIZE__	= 40K;

  __STACKSIZE__         = 1K;

  __vectors_load_start__ = ALIGN(__ESRAM_M3_start , 256);
  .vectors ALIGN(__ESRAM_M3_start , 256) : AT(__vectors_load_start__)
  {
    __vectors_start__ = .;
    *(.vectors .vectors.*)
    __vectors_end__ = .;
  } > ESRAM_M3
  __vectors_load_end__ = __vectors_load_start__ + SIZEOF(.vectors);

  . = ASSERT(__vectors_end__ <= __ESRAM_M3_end , "error: .vectors is too large to fit in RAM memory segment");

  /*
   * Attention!!!: don't move must be always address 0x100,
   * this fixed address is shared with flashLoader
   */
  FIXED_ADDR_DATA_load_start__ = ALIGN(__vectors_load_end__ , 4);
  FIXED_ADDR_DATA __vectors_end__ : AT(FIXED_ADDR_DATA_load_start__)
  {
	  __fixed_addr_data_start__ = .;
	  *(FIXED_ADDR_DATA)
	  __fixed_addr_data_end__ = .;
  } > ESRAM_M3
  FIXED_ADDR_DATA_load_end__ = FIXED_ADDR_DATA_load_start__ + SIZEOF(FIXED_ADDR_DATA);

  __roinitdata_load_start__ = ALIGN(FIXED_ADDR_DATA_load_end__ , 4);
  .roinitdata ALIGN(__fixed_addr_data_end__, 4) : AT(__roinitdata_load_start__)
  {
	  __roinitdata_start__ = .;
	  *(.roinitdata)
	  __roinitdata_end__ = .;
  } > ESRAM_M3
  __roinitdata_load_end__ = __roinitdata_load_start__ + SIZEOF(.roinitdata);

  __init_load_start__ = ALIGN(__roinitdata_load_end__ , 4);
  .init ALIGN(__roinitdata_end__ , 4) : AT(__init_load_start__)
  {
    __init_start__ = .;
    *(.init .init.*)
    *(.fini)
    __init_end__ = .;
  } > ESRAM_M3
  __init_load_end__ = __init_load_start__ + SIZEOF(.init);

  . = ASSERT(__init_end__ <= __ESRAM_M3_end , "error: .init is too large to fit in RAM memory segment");

  __text_load_start__ = ALIGN(__init_load_end__ , 4);
  .text ALIGN(__init_end__ , 4) : AT(__text_load_start__)
  {
    __text_start__ = .;
    *(.text .text.* .glue_7t .glue_7 .gnu.linkonce.t.* .gcc_except_table .ARM.extab* .gnu.linkonce.armextab.*)
    __text_end__ = .;
  } > ESRAM_M3
  __text_load_end__ = __text_load_start__ + SIZEOF(.text);

  . = ASSERT(__text_end__ <= __ESRAM_M3_end , "error: .text is too large to fit in RAM memory segment");


  __data_load_start__ = ALIGN(__text_load_end__ , 4);
  .data ALIGN(__text_end__ , 4) : AT(__data_load_start__)
  {
    __data_start__ = .;
    *(.data .data.* .gnu.linkonce.d.*)
    __data_end__ = .;
  } > ESRAM_M3
  __data_load_end__ = __data_load_start__ + SIZEOF(.data);

  . = ASSERT(__data_end__ <= __ESRAM_M3_end , "error: .data is too large to fit in RAM memory segment");

  __rodataexidx_load_start__ = ALIGN(__data_load_end__ , 4);
  .rodataexidx ALIGN(__data_end__ , 4) : AT(__rodataexidx_load_start__)
  {
    __rodataexidx_start__ = .;
    *(.ARM.exidx .ARM.exidx.*)
    __rodataexidx_end__ = .;
  } > ESRAM_M3
  __rodataexidx_load_end__ = __rodataexidx_load_start__ + SIZEOF(.rodataexidx);

  . = ASSERT(__rodataexidx_end__ <= __ESRAM_M3_end , "error: .rodataexidx is too large to fit in RAM memory segment");

  __rodata_load_start__ = ALIGN(__rodataexidx_load_end__ , 4);
  .rodata ALIGN(__rodataexidx_end__ , 4) : AT(__rodata_load_start__)
  {
    __rodata_start__ = .;
    *(.rodata .rodata.* .gnu.linkonce.r.*)
    *(.note.gnu.build-id .note.gnu.build-id.*)
    __rodata_end__ = .;
  } > ESRAM_M3
  __rodata_load_end__ = __rodata_load_start__ + SIZEOF(.rodata);

  . = ASSERT(__rodata_end__ <= __ESRAM_M3_end , "error: .rodata is too large to fit in RAM memory segment");

  __compressed_uboot_start__ = __rodata_end__;

  __code_and_data_size__ = __rodataexidx_load_end__ - __vectors_load_start__;
  . = ASSERT(__code_and_data_size__ <= __MAX_XLF_SIZE__ , "error: code and data size is too large limited to 20KB max");

  /* AP zipped loader is concatenated to M3 loader code by host flasher here */

  MBOX ALIGN(ORIGIN(ESRAM_AP) + __MBOX_OFFSET__, 4) (NOLOAD) :
  {
	  __MBOX_start__ = .;
	  . = __MBOX_start__ + __MBOX_SIZE__;
	  __MBOX_end__ = .;
  } > ESRAM_AP

#ifdef ATF
  MBOX_SEC ALIGN(ORIGIN(ESRAM_AP) + __MBOX_SEC_OFFSET__, 4) (NOLOAD) :
  {
	  __MBOX_SEC_start__ = .;
	  . = __MBOX_SEC_start__ + __MBOX_SEC_SIZE__;
	  __MBOX_SEC_end__ = .;
  } > ESRAM_AP
#endif

  /* BSS and stack are put at end of AP ESRAM */
  .bss ALIGN(__ESRAM_AP_segment_end__ - 0x10000, 4) (NOLOAD) :
  {
    __bss_start__ = .;
    *(.bss .bss.* .gnu.linkonce.b.*) *(COMMON)
    __bss_end__ = .;
  } > ESRAM_AP

  . = ASSERT(__bss_end__ <= __ESRAM_AP_segment_end__ , "error: .bss is too large to fit in AP RAM memory segment");

  .stack ALIGN(__bss_end__ , 4) (NOLOAD) :
  {
    __stack_start__ = .;
    *(.stack .stack.*)
    . = ALIGN(MAX(__stack_start__ + __STACKSIZE__ , .), 4);
    __stack_end__ = .;
  } > ESRAM_AP

  . = ASSERT(__stack_end__ <= __ESRAM_AP_segment_end__ , "error: .stack is too large to fit in AP RAM memory segment");

  .shared_data __ESRAM_AP_segment_end__ (NOLOAD) :
  {
    __shared_data_start__ = .;
    *(.shared_data)
    *(.shared_m3_data)
    __shared_data_end__ = .;
  } > ESRAM_AP
  . = ASSERT(__shared_data_end__ <= __ESRAM_AP_end , "error: shared_data is too large to fit in AP ESRAM memory segment");

}

