#pragma once

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libuv.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "http-parser.lib")
#define uv_sleep Sleep
#elif
#define uv_sleep sleep
#endif

#include <uv.h>
