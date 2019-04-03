#include "include/svm.h"

static const uint32_t msrpm_ranges[] = { 0, 0xc0000000, 0xc0010000 };

#define ARRAY_ELEMENTS(x) (sizeof(x)/sizeof((x)[0]))
#define NUM_MSR_MAPS ARRAY_ELEMENTS(msrpm_ranges)
#define MSRS_RANGE_SIZE 2048
#define MSRS_IN_RANGE (MSRS_RANGE_SIZE * 8 / 2)

uint32_t svm_msrpm_offset(uint32_t msr)
{
	uint32_t offset;
	int i;

	for (i = 0; i < NUM_MSR_MAPS; i++) {
		if (msr < msrpm_ranges[i] ||
			msr >= msrpm_ranges[i] + MSRS_IN_RANGE)
			continue;

		offset = (msr - msrpm_ranges[i]) / 4; /* 4 msrs per u8 */
		offset += (i * MSRS_RANGE_SIZE);       /* add range offset */

		/* Now we have the u8 offset - but need the u32 offset */
		return offset / 4;
	}

	/* MSR not in any range */
	return -1;
}