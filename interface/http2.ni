// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/url.ni";

/** @brief HTTP/2 admission, protocol and I/O failure categories. */
pub enum Http2ErrorKind {
  InvalidArgument,
  Closed,
  Busy,
  LimitExceeded,
  Protocol,
  StreamReset,
  UnexpectedEof,
  ResourceExhausted,
  Network,
  Tls,
  Negotiation,
  Provider
}

/** @brief HTTP/2 failure with a provider or stream error code when available. */
pub struct Http2Error {
  kind: Http2ErrorKind;
  code: int32;
  network: NetError?;
  provider: FfiError?;
}

/** @brief Zero selects 8 streams and 8 MiB per request/response body.
 * @note Maxima are 16 streams and 16 MiB per body. Header blocks are capped at 32 KiB. */
pub struct Http2Limits {
  max_streams: int32;
  max_body_bytes: int32;
}

/** @brief Complete response owning its fields and payload. Informational responses are skipped. */
pub struct Http2Response {
  status: int32;
  fields: Array<HttpField>;
  trailers: Array<HttpField>;
  body: ByteBuffer;
}

/** @brief Exclusive transport; methods borrow their buffers only during each call. */
pub interface Http2Transport {
  Read(buffer: ref NetMutableBytes, options: ref NetOperationOptions) -> Result<intptr, Http2Error>;
  WriteAll(buffer: ref NetBytes, options: ref NetOperationOptions) -> Result<Unit, Http2Error>;
  Abort() -> void;
}

/** @brief Single-caller HTTP/2 connection supporting multiple in-flight streams. */
pub struct Http2Client;

/** @brief Connect to http:// using cleartext prior knowledge.
 * @param provider_file Trusted path to the native HTTP/2 bridge shared library. */
pub static method(Http2Client) Open(
  url: ref HttpUrl, provider_file: ref string, resolver: ref mut AsyncResolver, dial: ref HttpDialOptions,
  limits: ref Http2Limits, options: ref NetOperationOptions
) -> Result<Http2Client, Http2Error>;

/** @brief Take exclusive ownership of an already connected HTTP/2 transport.
 * @note The URL fixes the scheme and origin. On failure the transport is aborted. */
pub static method(Http2Client) Adopt(
  transport: Http2Transport, url: ref HttpUrl, provider_file: ref string, limits: ref Http2Limits
) -> Result<Http2Client, Http2Error>;

/** @brief Queue a request and return its stream ID. The provider copies its body.
 * @note Requests on one connection share the opening origin. Include additional request
 * headers as lowercase or mixed case. The library owns pseudo headers and Content-Length.
 * Submit several requests before driving Receive to multiplex. */
pub method(Http2Client) Submit(
  url: ref HttpUrl, verb: ref string, fields: ref <HttpField>[], body: ref ByteBuffer
) -> Result<int32, Http2Error>;

/** @brief Drive the connection until the selected stream finishes and take its response once.
 * @note Other streams progress on the same connection. An I/O or connection error retires
 * the client; a stream reset retires only its stream. */
pub method(Http2Client) Receive(
  stream_id: int32, options: ref NetOperationOptions
) -> Result<Http2Response, Http2Error>;

/** @brief A live connection cannot be copied. */
pub method(Http2Client) operator copy() -> Http2Client = delete;

/** @brief Move the connection and all retained streams. */
pub method(Http2Client) operator move() -> Http2Client;

/** @brief Release the connection and retained stream state. */
pub method(Http2Client) operator drop() -> void;

/** @brief Abort the connection and release pending streams. */
pub method(Http2Client) Close() -> void;

/** @brief Validate public HTTP/2 session limits without network I/O. */
pub method(Http2Limits) IsValid() -> bool;
