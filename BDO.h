#pragma once

#include <stdint.h>
#include <cstring>


namespace BDO
{
	uint32_t decompress(uint8_t *in, uint8_t *out);
	uint32_t decompressEF(uint8_t* src, uint8_t* dst, int decomp_len);
//	uint32_t calculatePackCRC(uint8_t *data, uint32_t length);
}
