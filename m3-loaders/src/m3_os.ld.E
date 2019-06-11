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
  __HEAP_start         = DDRAM_M3_OS_HEAP_BASE; /* dynamic memory allocation in ddr */
  __HEAPSIZE__         = DDRAM_M3_OS_HEAP_SIZE;

#ifdef ATF
	/* No constraint with ATF, M3 OS is read by ATF not M3 XL */
	__MAX_XL_SIZE_TO_SHADOW__ = LENGTH(ESRAM_M3);
#else
	/* Size max, resident M3 xloader which loads M3 OS start there */
    __MAX_XL_SIZE_TO_SHADOW__ = 190K;
#endif
  __M3_SOFTWARE_END = __ESRAM_M3_start + ESRAM_M3_XL_SOFTWARE_BASE - ESRAM_M3_BASE + ESRAM_M3_XL_SOFTWARE_SIZE;
  /* The last ESRAM AP bytes are reserved for M3/AP shared data */
  __ESRAM_AP_segment_end__  = ESRAM_A7_SHARED_DATA_BASE;
  __MBOX_OFFSET__ = (ESRAM_A7_APP_OS_MAILBOXES_BASE - ESRAM_A7_BASE);
  __MBOX_SIZE__ = ESRAM_A7_APP_OS_MAILBOXES_SIZE;
#ifdef ATF
  __MBOX_SEC_OFFSET__ = (ESRAM_A7_ATF_IPC_BASE - ESRAM_A7_ATF_TRUSTED_ZONE_BASE);
  __MBOX_SEC_SIZE__ = ESRAM_A7_ATF_IPC_SIZE;
#endif
#ifdef ESRAM_A7_KS_MBX_BUFFER_BASE
  __KS_MBX_OFFSET__ = (ESRAM_A7_KS_MBX_BUFFER_BASE - ESRAM_A7_BASE);
#endif
  __SIGNATURE_LENGTH__ = 2K; /* FIXME must be updated to the max sign length */

  __STACKSIZE__         = 512;

  __vectors_load_start__ = ALIGN(__ESRAM_M3_start , 256);
  .vectors ALIGN(__ESRAM_M3_start , 256) : AT(__vectors_load_start__)
  {
    __vectors_start__ = .;
    *(.vectors .vectors.*)
    __vectors_end__ = .;
  } > ESRAM_M3
  __vectors_load_end__ = __vectors_load_start__ + SIZEOF(.vectors);

  . = ASSERT(__vectors_end__ <= __M3_SOFTWARE_END , "error: .vectors is too large to fit in RAM memory segment");

  __roinitdata_load_start__ = ALIGN(__vectors_load_end__ , 4);
  .roinitdata ALIGN(__vectors_load_end__, 4) : AT(__roinitdata_load_start__)
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

  . = ASSERT(__init_end__ <= __M3_SOFTWARE_END , "error: .init is too large to fit in RAM memory segment");

  /* rodata are gathered into another section for HSM tests vectors */
#ifdef EHSM_TEST
  __rodataexidx_load_start__ = ALIGN(__init_load_end__ , 4);

  .rodataexidx ALIGN(__init_load_end__ , 4) : AT(__rodataexidx_load_start__)
#else
  __rodata_load_start__ = ALIGN(__init_load_end__ , 4);
  .rodata ALIGN(__init_load_end__ , 4) : AT(__rodata_load_start__)
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
#endif
  {
    __rodataexidx_start__ = .;
    __exidx_start = .;
    *(.ARM.exidx .ARM.exidx.*)
    __exidx_end = .;
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

  . = ASSERT(__data_load_end__ <= __ESRAM_M3_start + __MAX_XL_SIZE_TO_SHADOW__ , "error: secondary code size is too large (192KB Max)");

  . = ASSERT(__data_end__ <= __M3_SOFTWARE_END , "error: .data is too large to fit in RAM memory segment");

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

  /* System config (TOC) is put at end of M3 ESRAM */
  .sysconfig ALIGN(__ESRAM_M3_start + ESRAM_M3_RUNTIME_TOC_BASE - ESRAM_M3_BASE, 4) (NOLOAD) :
  {
   __sysconfig_start__ = .;
   *(.sysconfig)
   __sysconfig_end__ = .;
  } > ESRAM_M3
  . = ASSERT(__sysconfig_end__ <= __ESRAM_M3_end , "error: .sysconfig is too large");


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

  .c3_programs ALIGN(4) (NOLOAD) :
  {
    __c3_programs_start__ = .;
    *(.c3_programs)
    __c3_programs_end__ = .;
  } > ESRAM_AP

#ifdef ESRAM_A7_KS_MBX_BUFFER_BASE
  .ks_mbx_buffer ALIGN(ORIGIN(ESRAM_AP) + __KS_MBX_OFFSET__, 4) (NOLOAD) :
  {
    __ks_mbx_buffer_start__ = .;
    *(.ks_mbx_buffer)
    __ks_mbx_buffers_end__ = .;
  } > ESRAM_AP
  . = ASSERT(SIZEOF(.ks_mbx_buffer) <= ESRAM_A7_KS_MBX_BUFFER_SIZE , "error: .ks_mbx_buffer is too large");
#endif

  .shared_data __ESRAM_AP_segment_end__ (NOLOAD) :
  {
    __shared_data_start__ = .;
    *(.shared_data)
    *(.shared_m3_data)
    __shared_data_end__ = .;
  } > ESRAM_AP
  . = ASSERT(__shared_data_end__ <= __ESRAM_AP_end , "error: shared_data is too large to fit in AP ESRAM memory segment");

  .heap ALIGN(__HEAP_start , 4) (NOLOAD) :
  {
    __heap_start__ = .;
    *(.heap .heap.*)
    . = ALIGN(MAX(__heap_start__ + __HEAPSIZE__ , .), 4);
    __heap_end__ = .;
  } > DRAM

}

#ifdef EHSM_TEST
SECTIONS
{
  /* Allocate area for HSM tests vectors at the end of TEE area */
  __EHSM_SIZE     = 4M;
  __EHSM_start    = DDRAM_ATF_TEE_BASE + DDRAM_ATF_TEE_SIZE - __EHSM_SIZE;
  __EHSM_end	  = __EHSM_start + __EHSM_SIZE;

  __rodata_load_start__ = ALIGN(__EHSM_start , 4);
  .rodata ALIGN(__EHSM_start , 4) : AT(__rodata_load_start__)
  {
    __rodata_start__ = .;
    *(.rodata .rodata.* .gnu.linkonce.r.*)
    *(.note.gnu.build-id .note.gnu.build-id.*)
    __rodata_end__ = .;
  } > DRAM
  __rodata_load_end__ = __rodata_load_start__ + SIZEOF(.rodata);

  . = ASSERT(__rodata_end__ <= __EHSM_end , "error: .rodata is too large to fit in RAM memory segment");
}
#endif

