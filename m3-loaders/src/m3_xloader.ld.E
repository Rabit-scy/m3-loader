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


  /*
   * Code and data are put at end of M3 ESRAM to be able to shadow M3 OS
   * into start of M3 ESRAM
   */
  __ESRAM_M3_CODE_OFFSET = 190K;
  __ESRAM_M3_CODE_START = __ESRAM_M3_start + __ESRAM_M3_CODE_OFFSET;
  __M3_SOFTWARE_END = __ESRAM_M3_start + ESRAM_M3_XL_SOFTWARE_BASE - ESRAM_M3_BASE + ESRAM_M3_XL_SOFTWARE_SIZE;

  __MAX_XL_SIZE_TO_SHADOW__ = 128K; /* Size of a NAND block */
  /* The 128 last ESRAM AP bytes are reserved for M3/AP shared data */
  __C3_PROG_OFFSET__ = 256K; /* Offset in AP ESRAM for C3 programs */
  __ESRAM_AP_segment_end__  = ESRAM_A7_SHARED_DATA_BASE;
  __SIGNATURE_LENGTH__ = 2K; /* FIXME must be updated to the max sign length */

  __STACKSIZE__         = 2K;

  __vectors_load_start__ = ALIGN(__ESRAM_M3_start , 256);
  .vectors ALIGN(__ESRAM_M3_start , 256) : AT(__vectors_load_start__)
  {
    __vectors_start__ = .;
    *(.vectors .vectors.*)
    __vectors_end__ = .;
  } > ESRAM_M3
  __vectors_load_end__ = __vectors_load_start__ + SIZEOF(.vectors);

  . = ASSERT(__vectors_end__ <= __ESRAM_M3_CODE_START , "error: .vectors is too large");

  __sysconfig_init_load_start__ = ALIGN(__vectors_load_end__ , 4);
  .sysconfig_init ALIGN(__vectors_end__, 4) : AT(__sysconfig_init_load_start__)
  {
   __sysconfig_init_start__ = .;
   *(.sysconfig_init)
   __sysconfig_init_end__ = .;
  } > ESRAM_M3
  __sysconfig_init_load_end__ = __sysconfig_init_load_start__ + SIZEOF(.sysconfig_init);

  __roinitdata_load_start__ = ALIGN(__sysconfig_init_load_end__ , 4);
  .roinitdata ALIGN(__sysconfig_init_end__, 4) : AT(__roinitdata_load_start__)
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

  . = ASSERT(__init_end__ <= __ESRAM_M3_CODE_START , "error: .init is too large");

  __rodata_load_start__ = ALIGN(__init_load_end__ , 4);
  .rodata ALIGN(__ESRAM_M3_CODE_START, 4) : AT(__rodata_load_start__)
  {
    __rodata_start__ = .;
    *(.rodata .rodata.* .gnu.linkonce.r.*)
    *(.note.gnu.build-id .note.gnu.build-id.*)
    __rodata_end__ = .;
  } > ESRAM_M3
  __rodata_load_end__ = __rodata_load_start__ + SIZEOF(.rodata);

  . = ASSERT(__rodata_end__ <= __M3_SOFTWARE_END , "error: .rodata is too large to fit in RAM memory segment");

  __rodataexidx_load_start__ = ALIGN(__rodata_load_end__ , 4);
  .rodataexidx ALIGN(__rodata_end__ , 4) : AT(__rodataexidx_load_start__)
  {
    __rodataexidx_start__ = .;
    *(.ARM.exidx .ARM.exidx.*)
    __rodataexidx_end__ = .;
  } > ESRAM_M3
  __rodataexidx_load_end__ = __rodataexidx_load_start__ + SIZEOF(.rodataexidx);

  . = ASSERT(__rodataexidx_end__ <= __M3_SOFTWARE_END , "error: .rodataexidx is too large to fit in RAM memory segment");

  __text_load_start__ = ALIGN(__rodataexidx_load_end__ , 4);
  .text ALIGN(__rodataexidx_end__ , 4) : AT(__text_load_start__)
  {
    __text_start__ = .;
    *(.text .text.*)
    *(.glue_7t .glue_7 .gnu.linkonce.t.* .gcc_except_table .ARM.extab* .gnu.linkonce.armextab.*)
    __text_end__ = .;
  } > ESRAM_M3
  __text_load_end__ = __text_load_start__ + SIZEOF(.text);

  . = ASSERT(__text_end__ <= __M3_SOFTWARE_END , "error: .text is too large to fit in RAM memory segment");

  __data_load_start__ = ALIGN(__text_load_end__ , 4);
  .data ALIGN(__text_end__ , 4) : AT(__data_load_start__)
  {
    __data_start__ = .;
    *(.data .data.* .gnu.linkonce.d.*)
    __data_end__ = .;
  } > ESRAM_M3
  __data_load_end__ = __data_load_start__ + SIZEOF(.data);

  __ap_xl_hash_start__ = __data_load_end__;

  . = ASSERT(__data_end__ + 32 <= __M3_SOFTWARE_END , "error: .data is too large to fit in RAM memory segment");

  . = ASSERT(__data_load_end__ + 32 <= __ESRAM_M3_start + __MAX_XL_SIZE_TO_SHADOW__ , "error: secondary code size is too large to fit in one NAND block (128KB)");

  /* Add a gap after text & data end for signature and aligned it with 512 */
  __bss_start_addr__ = ALIGN(__data_end__ + __SIGNATURE_LENGTH__, 512);
  .bss __bss_start_addr__ (NOLOAD) :
  {
    __bss_start__ = .;
    *(.bss .bss.* .gnu.linkonce.b.*) *(COMMON)
    __bss_end__ = .;
  } > ESRAM_M3

  . = ASSERT(__bss_end__ <= __M3_SOFTWARE_END , "error: .bss is too large to fit in RAM memory segment");

  .stack ALIGN(__bss_end__ , 4) (NOLOAD) :
  {
    __stack_start__ = .;
    *(.stack .stack.*)
    . = ALIGN(MAX(__stack_start__ + __STACKSIZE__ , .), 4);
    __stack_end__ = .;
  } > ESRAM_M3

  . = ASSERT(__stack_end__ <= __M3_SOFTWARE_END, "error: .stack is too large to fit in RAM memory segment");

  /* System config (runtime M3 TOC) is put at end of M3 ESRAM,
   * Attention!!!: It must be persistent for next M3 boot stages */
  .sysconfig ALIGN(__ESRAM_M3_start + ESRAM_M3_RUNTIME_TOC_BASE - ESRAM_M3_BASE, 4) (NOLOAD) :
  {
   __sysconfig_start__ = .;
   *(.sysconfig)
   __sysconfig_end__ = .;
  } > ESRAM_M3
  . = ASSERT(__sysconfig_end__ <= __ESRAM_M3_end , "error: .sysconfig is too large");

  .c3_programs ALIGN(ORIGIN(ESRAM_AP) + __C3_PROG_OFFSET__, 4) (NOLOAD) :
  {
    __c3_programs_start__ = .;
    *(.c3_programs)
    __c3_programs_end__ = .;
  } > ESRAM_AP
  . = ASSERT(__c3_programs_end__ <= __ESRAM_AP_segment_end__ , "error: __c3_programs_end__ is too large to fit in AP ESRAM memory segment");

  .shared_data __ESRAM_AP_segment_end__ (NOLOAD) :
  {
    __shared_data_start__ = .;
    *(.shared_data)
    *(.shared_m3_data)
    __shared_data_end__ = .;
  } > ESRAM_AP
  . = ASSERT(__shared_data_end__ <= __ESRAM_AP_end , "error: shared_data is too large to fit in AP ESRAM memory segment");

}

