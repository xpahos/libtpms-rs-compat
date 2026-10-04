#include "libtpms/tpm_library.h"
#if __has_include("tpms_cc_marker.h")
#include "tpms_cc_marker.h"
#else
#define TPMS_CC_MARKER "env-marker:absent"
#endif
#ifndef TPMS_CC_OPTION
#error "the option given in CC did not reach the compiler"
#endif
#define TPMS_TEXT(x) #x
#define TPMS_STRING(x) TPMS_TEXT(x)
const char tpms_cc_option[] = "cc-option:" TPMS_STRING(TPMS_CC_OPTION);
const char tpms_cc_marker[] = TPMS_CC_MARKER;
