// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

import "stdlib:stdlib.ny";
import "interface/http.ni";

/** @brief Cross-site policy for a serialized Set-Cookie field. */
pub enum HttpSameSite {
  Unspecified,
  Strict,
  Lax,
  None
}

/** @brief Attributes for a response cookie. Empty domain and path omit the attribute.
 * @note max_age is signed seconds. Nil omits Max-Age. A nonpositive value deletes the cookie. */
pub struct HttpCookieSettings {
  domain: string;
  path: string;
  max_age: int64?;
  secure: bool;
  http_only: bool;
  same_site: HttpSameSite;
}

/** @brief Strict Cookie request parsing and validated Cookie/Set-Cookie serialization.
 * @note Owns header syntax. Application code owns storage, expiry, origin and redirect policy. */
pub struct HttpCookie;

/** @brief Parse a Cookie field, retaining duplicate names in wire order.
 * @note Values are raw cookie octets, with an optional surrounding quote pair removed.
 *       Limits use max_head_bytes and max_fields. Invalid syntax yields Malformed. */
pub static method(HttpCookie) Parse(text: ref string, limits: ref HttpHeadLimits) -> Result<Array<HttpField>, HttpError>;

/** @brief Build one Cookie request field from validated raw name/value pairs.
 * @note Requires 1..128 pairs and at most 32 KiB of output. Field order is preserved.
 *       Values are never URL-decoded or comma-merged. */
pub static method(HttpCookie) Encode(fields: ref Array<HttpField>) -> Result<HttpField, HttpError>;

/** @brief Build one Set-Cookie response field with explicit attributes.
 * @note Enforces Secure for SameSite=None and the __Secure-/__Host- prefix rules.
 *       Invalid syntax returns InvalidArgument before publishing any field. */
pub static method(HttpCookie) Set(cookie: ref HttpField, settings: ref HttpCookieSettings) -> Result<HttpField, HttpError>;
