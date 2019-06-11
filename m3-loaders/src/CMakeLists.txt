# Common definitions and macros
add_definitions(-D${BOOT_DEVTYPE} -DSOC_ID=${SOC_ID} -DBOARD_ID=${BOARD_ID})

set(LINKER_FLAGS "-Wl,-n,--gc-sections,--cref,-Map")
set(OBJCOPY_OPTIONS -O binary)
set(OBJCOPY_OPTIONS_FILE1 -O binary)
set(OBJCOPY_OPTIONS_FILE2 -O binary)

# Create 1 output binary file
macro(st_add_postbuild_command target)
	add_custom_command(TARGET ${target} POST_BUILD
		COMMAND "${GNU_ARM_SIZE_TOOL}" $<TARGET_FILE:${target}>
		COMMAND "${GNU_ARM_OBJCOPY}" ${OBJCOPY_OPTIONS} $<TARGET_FILE:${target}> $<TARGET_FILE:${target}>.bin
		COMMENT "${target}.bin built"
		VERBATIM
	)
endmacro (st_add_postbuild_command)

# Create 2 output binary files
macro(st_add_postbuild_multi_out_command target)
	add_custom_command(TARGET ${target} POST_BUILD
		COMMAND "${GNU_ARM_SIZE_TOOL}" $<TARGET_FILE:${target}>
		COMMAND "${GNU_ARM_OBJCOPY}" ${OBJCOPY_OPTIONS_FILE1} $<TARGET_FILE:${target}> $<TARGET_FILE:${target}>.bin
		COMMAND "${GNU_ARM_OBJCOPY}" ${OBJCOPY_OPTIONS_FILE2} $<TARGET_FILE:${target}> $<TARGET_FILE:${target}>_file2.bin
		COMMENT "${target}.bin built"
		VERBATIM
	)
endmacro (st_add_postbuild_multi_out_command)

# Pre-process ld.E linker file to create output ld file
macro(preproc_ld target)
	add_custom_target(${target}
		COMMAND "${CMAKE_C_COMPILER}" -E -x c ${target}.E -I ${STA_MEM_MAP_DIR} ${PREPROC_FLAGS} | grep -v "^#" > ${target}
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
		SOURCES ${target}.E
		COMMENT "pre-processing ${target}"
		VERBATIM
	)
endmacro (preproc_ld)

# Pre-process ld.E linker file to create a 2nd output ld file
macro(preproc_ld_file2 target target2)
	add_custom_target(${target2}
		COMMAND "${CMAKE_C_COMPILER}" -E -x c ${target}.E -I ${STA_MEM_MAP_DIR} ${PREPROC_FLAGS_FILE2} | grep -v "^#" > ${target2}
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
		SOURCES ${target}.E
		COMMENT "pre-processing ${target2}"
		VERBATIM
	)
endmacro (preproc_ld_file2)

# Common library
set(common_SRCS
	init.c
	printf-stdarg.c
	trace.c
	sta_common.c
	sta_image.c
	syscalls.c
	debug_regs.c
)

add_library(common STATIC ${common_SRCS})

# eHSM configuration
if (EHSM_TEST)
	add_definitions(-DEHSM_TEST)
	set(PREPROC_FLAGS_FILE2 ${PREPROC_FLAGS} -DEHSM_TEST)

	# Split output binary in 2 files mapped in different memroy area 
	# 1 file with .rodata section including EHSM test vectors
	# 1 file with excluding the .rodata section
	set(OBJCOPY_OPTIONS_FILE1 ${OBJCOPY_OPTIONS_FILE1} -R .rodata)
	set(OBJCOPY_OPTIONS_FILE2 ${OBJCOPY_OPTIONS_FILE2} -j .rodata)
endif (EHSM_TEST)

# M3 xloader
set(m3_xloader_SRCS
	startup.s
	freeRTOS_stubs.c
	malloc_stubs.c
	sta_xloader.c
)

# M3 car radio application
set(m3_car_radio_SRCS
	startup.s
	sta_car_radio.c
)

# M3 telematics application
set(m3_telematics_SRCS
	startup.s
	sta_telematics.c
)

# Target to pass C pre-processor on .ld.E files
preproc_ld(m3_os.ld)
preproc_ld(m3_xloader.ld)
preproc_ld(m3_xl_uflashloader.ld)
if (EHSM_TEST)
	preproc_ld_file2(m3_os.ld m3_os_file2.ld)
endif (EHSM_TEST)

set_property(SOURCE startup.s PROPERTY LANGUAGE C)

add_executable(m3_xloader ${m3_xloader_SRCS})
add_dependencies(m3_xloader m3_xloader.ld)
target_link_libraries(m3_xloader
	"-T${CMAKE_CURRENT_SOURCE_DIR}/m3_xloader.ld -u pinmux_request -u i2c_init -u LLD_SSP_Init ${LINKER_FLAGS},m3_xloader.map"
	common
	platform
	stdrivers_noscheduler
	middleware
)

if (BOARD_ID MATCHES "TC3")
	if (EHSM_TEST)
		add_executable(m3_telematics ${m3_telematics_SRCS})
		add_dependencies(m3_telematics m3_os_file2.ld)
		target_link_libraries(m3_telematics
			"-T${CMAKE_CURRENT_SOURCE_DIR}/m3_os_file2.ld -u _sbrk_r -u pinmux_request -u i2c_init -u LLD_SSP_Init -u print_process_registers ${LINKER_FLAGS},m3_telematics.map"
			common
			services
			platform
			stdrivers
			middleware
			freeRTOS
		)
		# Add post-build commands to create output binary files
		st_add_postbuild_multi_out_command(m3_telematics)
	else (EHSM_TEST)
		add_executable(m3_telematics ${m3_telematics_SRCS})
		add_dependencies(m3_telematics m3_os.ld)
		target_link_libraries(m3_telematics
			"-T${CMAKE_CURRENT_SOURCE_DIR}/m3_os.ld -u _sbrk_r -u pinmux_request -u i2c_init -u LLD_SSP_Init -u print_process_registers ${LINKER_FLAGS},m3_telematics.map"
			common
			services
			platform
			stdrivers
			middleware
			freeRTOS
		)
		# Add post-build commands to create output binary files
		st_add_postbuild_command(m3_telematics)
	endif (EHSM_TEST)
else ()
	add_executable(m3_car_radio ${m3_car_radio_SRCS})
	add_dependencies(m3_car_radio m3_os.ld)
	target_link_libraries(m3_car_radio
		"-T${CMAKE_CURRENT_SOURCE_DIR}/m3_os.ld -u _sbrk_r -u pinmux_request -u i2c_init -u LLD_SSP_Init -u print_process_registers ${LINKER_FLAGS},m3_car_radio.map"
		common
		services
		platform
		stdrivers
		middleware
		freeRTOS
	)
	# Add post-build commands to create output binary files
	st_add_postbuild_command(m3_car_radio)
endif ()


#target_compile_definitions(m3_xloader PRIVATE
#	DEBUG;OTHER_OPTIONS
#)

# Add post-build commands to create output binary files
st_add_postbuild_command(m3_xloader)

# M3 xloader for u-boot base flashloader tool
set(m3_xl_uflashloader_SRCS
	startup.s
	freeRTOS_stubs.c
	sta_xl_uflashloader.c
)

add_executable(m3_xl_uflashloader ${m3_xl_uflashloader_SRCS})
add_dependencies(m3_xl_uflashloader m3_xl_uflashloader.ld)
target_link_libraries(m3_xl_uflashloader
	"-T${CMAKE_CURRENT_SOURCE_DIR}/m3_xl_uflashloader.ld ${LINKER_FLAGS} -u pinmux_request -u i2c_init -u LLD_SSP_Init -Wl,m3_xl_uflashloader.map"
	common
	platform
	stdrivers_noscheduler
	middleware
)
target_include_directories(m3_xl_uflashloader
	PRIVATE ${PROJECT_SOURCE_DIR}/middleware/liblzg/include
)
target_compile_definitions(m3_xl_uflashloader PRIVATE)
st_add_postbuild_command(m3_xl_uflashloader)

# M3 minimal executable
set(m3_mini_SRCS
	startup.s
	sta_m3_mini.c
)

add_executable(m3_mini ${m3_mini_SRCS})
add_dependencies(m3_mini m3_os.ld)
target_link_libraries(m3_mini
	"-T${CMAKE_CURRENT_SOURCE_DIR}/m3_os.ld ${LINKER_FLAGS} -u i2c_init -u LLD_SSP_Init -Wl,m3_mini.map"
	common
	services_noscheduler_verbose
	platform
	stdrivers_noscheduler_verbose
	middleware
	freeRTOS
)

target_compile_definitions(m3_mini PRIVATE)
st_add_postbuild_command(m3_mini)

