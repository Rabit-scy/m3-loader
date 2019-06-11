#include "jpegdecres.h"
#include "sta_rpmsg_mm.h"
#include "string.h"

static void *jpeg_ept;
static uint8_t jpeg_ip_status = RPMSG_MM_SHARED_RES_UNLOCKED;

int JpegDecCallback(struct s_rpmsg_mm_data *data, void *priv)
{
	if (!data)
		return -1;

	switch (RPMSG_MM_GET_INFO(data->info)) {
	case RPMSG_MM_SHARED_RES_STATUS_REQ:
		data->len = 1;
		data->info = RPMSG_MM_SHARED_RES_STATUS_ACK;
		data->data[0] = (jpeg_ip_status == RPMSG_MM_SHARED_RES_LOCKED ?
				 RPMSG_MM_HW_RES_G1 : 0);
		TRACE_INFO("return jpeg ip status = %d\n", data->data[0]);
		break;
	default:
		break;
	}
	return 0;
}

int JpegDecRpmsgRegistration(void)
{
	if (jpeg_ept)
		return 0;

	jpeg_ept = rpmsg_mm_register_local_endpoint(RPSMG_MM_EPT_CORTEXM_G1,
						    JpegDecCallback,
						    NULL);

	if (!jpeg_ept) {
		TRACE_INFO("Unable to book G1 hardware resource !!!\n");
		return -1;
	}
	return 0;
}

int JpegDecBookResource(void)
{
	int ret = 0;

	JpegDecRpmsgRegistration();
	ret = rpmsg_mm_lock_resource(jpeg_ept,
				     RPMSG_MM_SHARED_RES_LOCKED,
				     RPMSG_MM_HW_RES_G1,
				     RPSMG_MM_EPT_CORTEXA_G1);
	if (ret >= 0)
		jpeg_ip_status = RPMSG_MM_SHARED_RES_LOCKED;
	return ret;
}

int JpegDecFreeResource(void)
{
	int ret = 0;

	JpegDecRpmsgRegistration();
	ret = rpmsg_mm_lock_resource(jpeg_ept,
				     RPMSG_MM_SHARED_RES_UNLOCKED,
				     RPMSG_MM_HW_RES_G1,
				     RPSMG_MM_EPT_CORTEXA_G1);
	if (ret >= 0)
		jpeg_ip_status = RPMSG_MM_SHARED_RES_UNLOCKED;

	return ret;
}
