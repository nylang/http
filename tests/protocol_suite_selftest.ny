// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief HTTP contract tests across independent implementation modules. */
module HttpProtocolTests;
part "head_selftest.ny";
part "body_selftest.ny";
part "framing_selftest.ny";
import "stdlib:stdlib.ny";
import "ntest:ntest.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/client.ni";
import "interface/url.ni";
import "interface/redirect.ni";
import "private/grammar.ny";
import "private/http.ny";
import "private/writer.ny";
import "private/body.ny";
import "private/body_writer.ny";
import "private/response.ny";
import "private/exchange.ny";
import "private/tcp_client.ny";
import "private/url.ny";
import "private/url_reference.ny";
import "private/url_dial.ny";
import "private/redirect.ny";
