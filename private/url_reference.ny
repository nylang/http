// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief URI reference resolution and origin comparison without redirect-chain state. */
module HttpUrlReference;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/url.ni";
import "interface/redirect.ni";
import "private/grammar.ny";
import "private/url.ny";

/** @brief Shared URI-reference resolution and explicit redirect/replay policy. */

func redirect_last_slash(text: ref string) -> int32 {
  var i: int32 = text.length - 1;
  while i >= 0 {
    if text[i] == '/' {
      return i;
    }

    i = i - 1;
  }

  return -1;
}

func redirect_remove_last(text: ref string) -> string {
  let slash: int32 = redirect_last_slash(text);
  if slash < 0 {
    return "";
  }

  return text.Substring(0, slash);
}

func redirect_dot_segments(path: ref string) -> string {
  var input: string = path;
  var output: string = "";
  while input.length != 0 {
    if input.StartsWith("../") {
      input = input.Substring(3, input.length - 3);
    } else if input.StartsWith("./") {
      input = input.Substring(2, input.length - 2);
    } else if input.StartsWith("/./") {
      input = input.Substring(2, input.length - 2);
    } else if input.Equal("/.") {
      input = "/";
    } else if input.StartsWith("/../") {
      input = input.Substring(3, input.length - 3);
      output = redirect_remove_last(output);
    } else if input.Equal("/..") {
      input = "/";
      output = redirect_remove_last(output);
    } else if input.Equal(".") || input.Equal("..") {
      input = "";
    } else {
      var end: int32 = 0;
      if input[0] == '/' {
        end = 1;
      }

      while end < input.length && input[end] != '/' {
        end = end + 1;
      }

      output = output.Concat(input.Substring(0, end));
      input = input.Substring(end, input.length - end);
    }
  }

  return output;
}

/**
 * @brief Resolve an ASCII URI-reference against this absolute URL using literal dot-segment
 *   removal.
 * @returns Ok with HttpUrl on success; Err with HttpError on the failure paths described above.
 * @note Validates before normalization, never percent-decodes; fragments are validated then
 *   omitted. Empty/query/fragment references retain the appropriate base path/query. Strict URL
 *   host/port rules still apply; non-HTTP schemes, userinfo, IDNA and scoped IPv6 remain
 *   unsupported.
 */
pub method(HttpUrl) Resolve(reference: ref string) -> Result<HttpUrl, HttpError> {
  if !self.IsValid() {
    return HttpMakeError(HttpErrorKind.InvalidArgument);
  }

  if reference.length > 8192 {
    return HttpMakeError(HttpErrorKind.LimitExceeded);
  }

  let origin: string = self.Scheme().Concat("://").Concat(self.HostField());
  var target: string = self.Target();
  let query: int32 = target.Find("?");
  if query >= 0 {
    target = target.Substring(0, query);
  }

  var colon: int32 = 0;
  while colon < reference.length
    && reference[colon] != ':'
    && reference[colon] != '/'
    && reference[colon] != '?'
    && reference[colon] != '#' {
    colon = colon + 1;
  }

  var absolute: string = "";
  if colon < reference.length && reference[colon] == ':' {
    absolute = reference;
  } else if reference.StartsWith("//") {
    absolute = self.Scheme().Concat(":").Concat(reference);
  } else if reference.StartsWith("/") {
    absolute = origin.Concat(reference);
  } else if reference.StartsWith("?") {
    absolute = origin.Concat(target).Concat(reference);
  } else if reference.length == 0 || reference.StartsWith("#") {
    absolute = self.ToString().Concat(reference);
  } else {
    let slash: int32 = redirect_last_slash(target);
    absolute = origin.Concat(target.Substring(0, slash + 1)).Concat(reference);
  }

  let checked: Result<HttpUrl, HttpError> = HttpUrl.Parse(absolute);
  if checked.IsErr() {
    return (checked.get_if<HttpError>()) as HttpError;
  }

  let raw: HttpUrl = (checked.get_if<HttpUrl>()) as HttpUrl;
  if reference.length == 0 || reference.StartsWith("?") || reference.StartsWith("#") {
    return raw;
  }

  var path: string = raw.Target();
  var suffix: string = "";
  let mark: int32 = path.Find("?");
  if mark >= 0 {
    suffix = path.Substring(mark, path.length - mark);
    path = path.Substring(0, mark);
  }

  return HttpUrl.Parse(
    raw.Scheme().Concat("://").Concat(raw.HostField()).Concat(redirect_dot_segments(path)).Concat(suffix)
  );
}

/**
 * @brief Compare canonical scheme, host and effective port; invalid URLs never match.
 * @returns Compare canonical scheme, host and effective port; invalid URLs never match.
 */
pub method(HttpUrl) SameOrigin(other: ref HttpUrl) -> bool {
  return self.IsValid()
    && other.IsValid()
    && self.Scheme().Equal(other.Scheme())
    && self.Host().Equal(other.Host())
    && self.Port() == other.Port();
}
