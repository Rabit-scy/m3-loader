set(jpeg_SRCS
	common/bqueue.c
	common/tiledref.c
	common/errorhandling.c
	common/commonconfig.c
	common/workaround.c
	common/refbuffer.c
	common/regdrv.c
	pp/ppinternal.c
	pp/ppapi.c
	jpeg/jpegdecapi.c
	jpeg/jpegdecutils.c
	jpeg/jpegdecscan.c
	jpeg/jpegdechdrs.c
	jpeg/jpegdecinternal.c
	jpeg/dwl.c
	jpeg/jpegdecres.c
)

# JPEG decoder configuration
add_definitions(-DFIFO_DATATYPE=i32)
add_definitions(-D_ASSERT_USED)
#add_definitions(-DJPEGDEC_ASIC_TRACE)
add_definitions(-DJPEGDEC_TRACE)
add_definitions(-D_ERROR_PRINT)
add_definitions(-D_DEBUG_PRINT)

# PP configuration
#add_definitions(-DJPEGDEC_PP_TRACE)
add_definitions(-DPP_JPEGDEC_PIPELINE_SUPPORT)

add_definitions(-DPP_TRACE)
add_definitions(-D_PPDEBUG_PRINT)
add_definitions(-D_TRACE_PP_CTRL)

# INClude files
include_directories(${PROJECT_SOURCE_DIR}/drivers/jpegdec/source/inc)
include_directories(${PROJECT_SOURCE_DIR}/drivers/jpegdec/source/config)
include_directories(${PROJECT_SOURCE_DIR}/drivers/jpegdec/source/common)
include_directories(${PROJECT_SOURCE_DIR}/drivers/jpegdec/source/jpeg)
include_directories(${PROJECT_SOURCE_DIR}/drivers/jpegdec/source/pp)
include_directories(${PROJECT_SOURCE_DIR}/services/inc/)


add_library(jpegdriver OBJECT ${jpeg_SRCS})


