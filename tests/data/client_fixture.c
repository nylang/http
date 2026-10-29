// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/* Explicit runtime configuration for external loopback consumers only. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
int32_t HttpFixturePort(void) { const char *s=getenv("HTTP_TEST_PORT"); return s?atoi(s):0; }
int32_t HttpFixtureCase(void) { const char *s=getenv("HTTP_TEST_CASE"); return s?atoi(s):0; }
const char *HttpFixtureCa(void) { const char *s=getenv("HTTP_TEST_CA"); return s?s:""; }
int32_t HttpFixtureCaLength(void) { return (int32_t)strlen(HttpFixtureCa()); }
