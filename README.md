# authenticator-python

<!-- vscode-markdown-toc -->
* [Prereqs](#Prereqs)
* [gRPC and protobuf generated code.](#gRPCandprotobufgeneratedcode.)
		* [Optional: Run `buf` to generate the Python code](#Optional:RunbuftogeneratethePythoncode)
	* [Starting the server](#Startingtheserver)
	* [Testing using the local client](#Testingusingthelocalclient)
* [TLS mode](#TLSmode)

<!-- vscode-markdown-toc-config
	numbering=false
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->



Very simple Python prototype of the Authorizer. We're not even trying to be a
real authorization server, we're just interested in knowing the gRPC language
and returning useful responses to test the RGW implementation.

## <a name='Prereqs'></a>Prereqs

```sh
pip3 install grpcio grpcio-status grpcio-tools coloredlogs
```

## <a name='gRPCandprotobufgeneratedcode.'></a>gRPC and protobuf generated code.

To reduce friction I've added the gRPC generated code into this repository. If
you need to regenerate it, you'll need the gRPC toolchain and the buf utility
in your path.

#### <a name='Optional:RunbuftogeneratethePythoncode'></a>Optional: Run `buf` to generate the Python code

```sh
buf generate
```

If buf isn't installed, [install it](https://buf.build/docs/installation). The
'Source' install option is pretty reliable, but you need Go installed. I'm not
going to document how to install Go here.

If `buf` complains about missing gRPC tools, you'll need to install those. I
use `grpc_python_plugin` built from the gRPC source, because our Ceph builds
gRPC from source. If you have a Ceph build setup you can build this yourself
with `ninja grpc_python_plugin`. It goes into `BUILDDIR/bin`; add this to
your PATH.

`buf generate` will put its output in `authenticator/v1/`, which is set up to
be a Python module that can be imported directly.

### <a name='Startingtheserver'></a>Starting the server

```sh
# Start an authenticator server on port 8001.
./authorizer_server.py

# Start on a different port.
./authorizer_server.py 8002

# Start in verbose mode (useful!)
./authorizer_server.py --verbose
```

The server can be stopped with CTRL-C.

### <a name='Testingusingthelocalclient'></a>Testing using the local client

XXX

## <a name='TLSmode'></a>TLS mode

The server and client can run with TLS enabled. For now, it's very simple TLS,
wherein the server has a key and certificate which the client can verify when
it has the CA certificate.

If mTLS is deemed necessary, we should update accordingly.

```sh
# Set up credentials for TLS run.
cd credentials # This directory.
./create_ca.sh
./create_cert.sh -a "subjectAltName = DNS:localhost,IP:127.0.0.1" localhost localhost

# Go back to the parent directory and run the server with TLS enabled.
./authorizer_server.py --verbose -t --server-cert=credentials/localhost.crt --server-key=credentials/localhost.key

# ... in a separate terminal ...

# Now the client examples will work if you give them the TLS root cert.
./authorizer_client.py -v auth -t --ca-cert=credentials/root.crt \
  --string-to-sign="QVdTNC1ITUFDLVNIQTI1NgoyMDIzMTExM1QxNTA4MzNaCjIwMjMxMTEzL3VzLWVhc3QtMS9zMy9hd3M0X3JlcXVlc3QKOTFmM2ZlYmQ1NjFhMTgyNDU1M2RmNTQxMzJiMDVhNGFjZDk2ZDRlOTI4OWE0M2EzMWM5YmY5NWM5M2Q3OTY5Ng==" \
  --authorization-header="AWS4-HMAC-SHA256 Credential=0555b35654ad1656d804/20231113/us-east-1/s3/aws4_request, SignedHeaders=content-md5;host;x-amz-content-sha256;x-amz-date, Signature=2d139a3564b7795d859f5ce788b0d7a0f0c9028c8519b381c9add9a72345aace"

DEBUG:root:using server_address dns:127.0.0.1:8002
```

