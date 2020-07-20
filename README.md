# WAF extension on Envoy proxy

This repository is forked from `envoyproxy/envoy-wasm`, and the example WASM
extension in the envoy-wasm repository is modified to work as a Web Application Firewall(WAF) that
can detect SQL injection. The rules for detection are aligned with ModSecurity
rules 942100 and 942101, and SQL injection is detected with methods from
libinjection.

### Deployment
From the root of the repository, build static binary of envoy proxy:

```bazel build -c opt //source/exe:envoy-static```

Run tests for envoy to make sure the binary has been built successfully:

```bazel test //test/common/common/...```

The source code for the WASM extension is in `examples/wasm`. Build the WASM module:

```bazel build //examples/wasm:envoy_filter_http_wasm_example.wasm```

The WASM binary being built will be at
`bazel-bin/examples/wasm/envoy_filter_http_wasm_example.wasm`. Make sure that the `filename` path in `examples/wasm/envoy.yaml` matches the path to the WASM binary. Then Run the WASM module:

``` ``sudo bazel-bin/source/exe/envoy-static -l trace --concurrency 1 -c
`pwd`/examples/wasm/envoy.yaml`` ```

In a separate terminal, curl at `localhost:80` to interact with the running proxy.

### Configuration
The rules for SQL injection detection can be configured from the YAML file. An example of configuration can be found in `examples/wasm/envoy-config.yaml`. 


