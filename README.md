# WAF extension on Envoy proxy

This repository is forked from `envoyproxy/envoy-wasm`, and the example WASM
extension in the envoy-wasm repository is modified to work as a Web Application Firewall(WAF) that
can detect SQL injection. The rules for detection are aligned with ModSecurity
rules 942100 and 942101, and SQL injection is detected with methods from
libinjection.

## Deployment
From the root of the repository, build static binary of envoy proxy:

```bazel build -c opt //source/exe:envoy-static```

Run tests for envoy to make sure the binary has been built successfully:

```bazel test //test/common/common/...```

The source code for the WASM extension is in `examples/wasm`. Build the WASM module:

```bazel build //examples/wasm:envoy_filter_http_wasm_example.wasm```

The WASM binary being built will be at
`bazel-bin/examples/wasm/envoy_filter_http_wasm_example.wasm`. Make sure that the `filename` path in `examples/wasm/envoy.yaml` matches the path to the WASM binary. Then Run the WASM module:

``` ``sudo bazel-bin/source/exe/envoy-static -l trace --concurrency 1 -c
`pwd`/examples/wasm/envoy.yaml ```

In a separate terminal, curl at `localhost:80` to interact with the running proxy.

## Configuration
The rules for SQL injection detection can be configured from the YAML file. An example of configuration can be found in `examples/wasm/envoy-config.yaml`. Configuration are passsed through the field `config.config.configuration.value` in the yaml file in JSON syntax as below:

```
{
	“query_param”: 
{
	# detect sqli on all parameters but “foo”
	“Content-Type”: “application/x-www-form-urlencoded”,
		“exclude”: “foo”,
},
“header”:
	{
		# detect sqli on “bar”, “Referrer”, and “User-Agent”
		“include”: “bar”,
	},
}
```
There are three parts that can be configured for now: query parameters(`query_param`), cookies(`cookie`, not shown above), and headers(`header`). Configuration for all three parts are optional. If nothing is passed in a field, a default configuration based on ModSecurity rule 942100 will apply.

### Query Parameters
The "Content-Type" field is required in query parameters configuration, Currently, the WASM module only supports SQL injection detection for the content type "application/x-www-form-urlencoded" (it has the syntax `param=value&param2=value2`). If the incoming http request has a different content type, detection on its body will be skipped.

In default setting, all query parameter names and values will be checked for SQL injection. To change this setting, you can either add an `include` or an `exclude` field. Both take a list of parameter names. If `include` is present, only the parameters in the list will be checked. If `exclude` is present, all but the parameters in the list will be checked. `include` and `exclude` are not expected to be present at the same time.

### Headers
In default setting, the `Referrer` and `User-Agent` headers will be checked for SQL injection. The `include` and `exclude` fields work similarly as above, except that `Referrer` and `User-Agent` will always be checked unless explicitly enlisted in `exlude`.

### Cookies
In default setting, all cookie names will be checked. `include` and `exclude` work exactly the same as for query parameters.
