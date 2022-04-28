#pragma once

#include <string>
#include "Windows.h"

std::string MBstr_to_UTFstr_WinAPI(std::string multibyte_str);
std::string decode_filename(uint8_t*& ptr);