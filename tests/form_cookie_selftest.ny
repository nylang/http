// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

import "stdlib:stdlib.ny";
import "ntest:ntest.ny";
import "forms.ny";
import "cookies.ny";
import "interface/http.ni";

@test(tag = "http_core")
func test_http_form_roundtrips_unicode_empty_values_and_duplicate_names() {
  let parsed = HttpForm.Parse("a=one+two&a=%E7%8C%AB&empty&=v&&escaped=%2B%26%3D%00", HttpFormLimits{});
  AssertTrue(parsed.IsOk());
  let fields = parsed.get_if<Array<HttpField>>()!;
  AssertEqI32(fields.Len(), 5);
  AssertEqString(fields.Get(0).value, "one two");
  AssertEqString(fields.Get(1).value, "猫");
  AssertEqString(fields.Get(2).value, "");
  AssertEqString(fields.Get(3).name, "");
  let encoded = HttpForm.Encode(fields, HttpFormLimits{}).get_if<string>()!;
  AssertEqString(encoded, "a=one+two&a=%E7%8C%AB&empty=&=v&escaped=%2B%26%3D%00");
  let query = HttpForm.ParseQuery("/resource?a=x%2Fy&a=z", HttpFormLimits{}).get_if<Array<HttpField>>()!;
  AssertEqI32(query.Len(), 2);
  AssertEqString(query.Get(0).value, "x/y");
}

@test(tag = "http_core")
func test_http_form_rejects_malformed_and_oversized_input_without_partial_results() {
  AssertTrue(HttpForm.Parse("a=1&b=%", HttpFormLimits{}).IsErr());
  AssertTrue(HttpForm.Parse("a=%GG", HttpFormLimits{}).IsErr());
  AssertTrue(HttpForm.Parse("a=%C0%AF", HttpFormLimits{}).IsErr());
  AssertTrue(HttpForm.Parse("a=1&b=2", HttpFormLimits{max_fields: 1}).IsErr());
  AssertTrue(HttpForm.Parse("a=1", HttpFormLimits{max_bytes: 2}).IsErr());
  AssertTrue(HttpForm.ParseQuery("/a?q=x#fragment", HttpFormLimits{}).IsErr());
  var fields = Array<HttpField>.New();
  fields.Push(HttpField{name: "猫", value: ""});
  AssertTrue(HttpForm.Encode(fields, HttpFormLimits{max_bytes: 9}).IsErr());
  AssertEqString(HttpForm.Encode(fields, HttpFormLimits{max_bytes: 10}).get_if<string>()!, "%E7%8C%AB=");
}

@test(tag = "http_core")
func test_http_cookie_preserves_order_and_raw_values_and_rejects_injection() {
  let parsed = HttpCookie.Parse("a=x%20y; a=\"second\"; empty=", HttpHeadLimits{});
  AssertTrue(parsed.IsOk());
  let fields = parsed.get_if<Array<HttpField>>()!;
  AssertEqI32(fields.Len(), 3);
  AssertEqString(HttpCookie.Encode(fields).get_if<HttpField>()!.value, "a=x%20y; a=second; empty=");
  AssertTrue(HttpCookie.Parse("a=ok\r\nInjected: x", HttpHeadLimits{}).IsErr());
  AssertTrue(HttpCookie.Parse("a=x;", HttpHeadLimits{}).IsErr());
  AssertTrue(HttpCookie.Parse("a=x; b=y", HttpHeadLimits{max_fields: 1}).IsErr());
  AssertTrue(HttpCookie.Parse("a=one,two", HttpHeadLimits{}).IsErr());
  AssertTrue(HttpCookie.Parse("", HttpHeadLimits{}).IsErr());
  let empty = Array<HttpField>.New();
  AssertTrue(HttpCookie.Encode(empty).IsErr());
}

@test(tag = "http_core")
func test_http_cookie_response_attributes_and_prefix_rules() {
  let cookie = HttpField{name: "__Host-session", value: "abc"};
  let settings = HttpCookieSettings{path: "/", secure: true, http_only: true, max_age: 60i64, same_site: HttpSameSite.Lax};
  let field = HttpCookie.Set(cookie, settings).get_if<HttpField>()!;
  AssertEqString(field.name, "Set-Cookie");
  AssertEqString(field.value, "__Host-session=abc; Path=/; Max-Age=60; Secure; HttpOnly; SameSite=Lax");
  AssertTrue(HttpCookie.Set(cookie, HttpCookieSettings{path: "/"}).IsErr());
  AssertTrue(HttpCookie.Set(cookie, HttpCookieSettings{path: "/", secure: true, domain: "example.test"}).IsErr());
  AssertTrue(HttpCookie.Set(HttpField{name: "a", value: "x"}, HttpCookieSettings{same_site: HttpSameSite.None}).IsErr());
  AssertTrue(HttpCookie.Set(HttpField{name: "a", value: "x"}, HttpCookieSettings{path: "/; Secure"}).IsErr());
}
