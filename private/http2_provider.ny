// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Loads the native HTTP/2 bridge and owns its call targets. */
module Http2NativeProvider;
import "stdlib:stdlib.ny";
import "interface/http2.ni";

/** @brief Borrowed native HTTP/2 header field used at the provider ABI boundary.
 */
pub struct Http2NativeField {
  name: *const uint8;
  value: *const uint8;
  name_size: int32;
  value_size: int32;
}

typedef OpenHttp2Provider = cfn<(int32, *mut Http2ProviderApi) -> int32>;

/** @brief Versioned native HTTP/2 function table retained by the loaded provider.
 */
pub struct Http2ProviderApi {
  create_session: cfn<(int32, int32) -> *mut int8>;
  drop_session: cfn<(*mut int8) -> void>;
  output: cfn<(*mut int8, *mut *const uint8) -> intptr>;
  input: cfn<(*mut int8, *const uint8, intptr) -> intptr>;
  wants_input: cfn<(*mut int8) -> int32>;
  submit: cfn<(*mut int8, *const Http2NativeField, int32, *const uint8, int32, *mut int32, *mut int32) -> int32>;
  stream: cfn<(*mut int8, int32, *mut int32, *mut int32, *mut int32, *mut int32, *mut *const uint8, *mut int32) -> int32>;
  field: cfn<(*mut int8, int32, int32, *mut Http2NativeField) -> int32>;
  release_stream: cfn<(*mut int8, int32) -> void>;
}

/** @brief Owner of the dynamic library and its validated HTTP/2 function table.
 */
pub struct Http2Provider {
  library: DynamicLibrary;
  api: Http2ProviderApi;
}

// nyra-lint-allow: prefer-type-owned-functions -- Noncapturing Result.visit success callback.
func symbol_address(value: *mut void) -> uintptr {
  return value as uintptr;
}

// nyra-lint-allow: prefer-type-owned-functions -- Noncapturing Result.visit error callback.
func missing_symbol(_error: FfiError) -> uintptr {
  return 0up;
}

/** @brief Load and validate the versioned native HTTP/2 provider entry.
 * @returns An owned provider or a dynamic-library, symbol or version error.
 */
pub static method(Http2Provider) Load(path: ref string) -> Result<Http2Provider, Http2Error> {
  var loaded = DynamicLibrary.Load(path);
  if loaded.IsErr() {
    return Http2Error{kind: Http2ErrorKind.Provider, provider: loaded.get_if<FfiError>()};
  }

  var library = move(loaded.get_if<DynamicLibrary>() as DynamicLibrary);
  let entry = library.GetSymbol("nyra_http2_provider");
  let address = entry.visit(symbol_address, missing_symbol);
  if address == 0up {
    return Http2Error{kind: Http2ErrorKind.Provider, provider: entry.get_if<FfiError>()};
  }

  var api = Http2ProviderApi{};
  unsafe {
    let open = address as OpenHttp2Provider;
    if open(1, &mut api) != 1 {
      return Http2Error{kind: Http2ErrorKind.Provider, provider: FfiError.NotSupported};
    }
  }

  return Http2Provider{library: move(library), api: api};
}
