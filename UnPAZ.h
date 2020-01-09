#pragma once

#include <stdio.h>
#include <tchar.h>
#include <string>
#include <iostream>

#if _MSC_VER >= 1910 && _MSC_VER < 1924
#include <filesystem>
#else
#include <boost/filesystem.hpp>    ///boost headers (for GCC add linker arguments: -lboost_system-mt -lboost_filesystem-mt)
#endif