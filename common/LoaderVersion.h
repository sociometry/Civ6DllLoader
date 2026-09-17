#pragma once

// Shared by C++ and RC: the RCDATA 105 version resource and kLoaderRuntimeVersion come from these.
#define CIV6_DLL_LOADER_VERSION_MAJOR 1
#define CIV6_DLL_LOADER_VERSION_MINOR 0
#define CIV6_DLL_LOADER_VERSION_PATCH 0

// RCDATA: magic(DWORD), format/major/minor/patch(WORD).
// This identifies a format, not an authenticated publisher.
#define CIV6_DLL_LOADER_VERSION_RESOURCE_ID 105
#define CIV6_DLL_LOADER_VERSION_MAGIC 0x54523643L
#define CIV6_DLL_LOADER_VERSION_FORMAT 1
