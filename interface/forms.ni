// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

import "stdlib:stdlib.ny";
import "interface/http.ni";

/** @brief Bounds on URL-encoded input/output bytes and ordered name/value pairs.
 * @note Zero selects 1 MiB and 1024 fields. Hard ceilings are 16 MiB and 65536 fields. */
pub struct HttpFormLimits {
  max_bytes: int32;
  max_fields: int32;
}

/** @brief Strict UTF-8 application/x-www-form-urlencoded codec with ordered duplicate fields. */
pub struct HttpForm;

/** @brief Decode name/value pairs, converting plus to space and percent escapes to UTF-8 bytes.
 * @note Empty segments are skipped. Invalid escapes and malformed UTF-8 return Malformed.
 *       No partial array escapes on failure. Names and values own their storage. */
pub static method(HttpForm) Parse(text: ref string, limits: ref HttpFormLimits) -> Result<Array<HttpField>, HttpError>;

/** @brief Decode the query after the first question mark in a request target.
 * @note A target without a query returns an empty array. Fragment markers are rejected. */
pub static method(HttpForm) ParseQuery(target: ref string, limits: ref HttpFormLimits) -> Result<Array<HttpField>, HttpError>;

/** @brief Encode valid UTF-8 fields in order, preserving duplicate names and empty values.
 * @note Spaces use plus. Reserved bytes use uppercase percent escapes. */
pub static method(HttpForm) Encode(fields: ref Array<HttpField>, limits: ref HttpFormLimits) -> Result<string, HttpError>;
