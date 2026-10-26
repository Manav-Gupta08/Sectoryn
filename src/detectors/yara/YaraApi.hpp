#pragma once

// libyara's public headers include <windows.h> on Windows; keep its min/max macros and rarely
// used APIs out of Sectoryn's code.
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include <yara.h>
