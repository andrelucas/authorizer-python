# authenticator-python

<!-- vscode-markdown-toc -->
* [Prereqs](#Prereqs)
* [gRPC and protobuf generated code.](#gRPCandprotobufgeneratedcode.)
		* [Optional: Run `buf` to generate the Python code](#Optional:RunbuftogeneratethePythoncode)
	* [Starting the server](#Startingtheserver)
	* [Default server buckets](#Defaultserverbuckets)
	* [Testing using the local client](#Testingusingthelocalclient)
* [(Not in use or tested) TLS mode](#NotinuseortestedTLSmode)

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

Note that you shouldn't need to do this unless you're changing the protobuf.

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
# Start an authenticator server on port 8003.
./authorizer_server.py

# Start on a different port.
./authorizer_server.py 8083

# Start in verbose mode (useful!)
./authorizer_server.py -v

# Start with 'reload' (for developing the server) to automatically restart on
# any working dir changes.
pip3 install reload
hash -r
reload ./authorizer_server.py -v
```

The server can be stopped with CTRL-C.

### <a name='Defaultserverbuckets'></a>Default server buckets

By default, the server sets up a few buckets with 'policies' that allow you to
test against basic expectations.

| *Bucket* | *Policy* | *Purpose* |
| -------- | -------- | ---------- |
| bucket1 | Always allow | |
| bucket2 | Always deny | |
| bucket3 | Allow, but ask for extra data if none are provided | Test that the RGW client properly appends extra data if requested. |
| bucket4 | Always ask for extra data | Test that the RGW client doesn't allow extra data loops. |

### 'Magic' auto-created buckets

To make scripted testing easier, the server will automatically create buckets
whenever it sees an authorization request for a create-bucket op. The policy
attached to the bucket will be assigned based on the bucket's name:

| *Bucket name pattern* | Policy |
| --- | --- |
| `.*1[a-z]$` | Always allow |
| `.*2[a-z]$` | Always deny |
| `.*3[a-z]$` | Allow, but ask for extra data if non are provided |
| `.*4[a-z]$` | Always ask for extra data |

Obviously this matches the default server buckets listed above. It allows
scripts to create a bucket with name, say, `test-20241007-1225-1` and because
it ends in '1' (with an optional letter suffix) it will be assigned the
'always allow' policy.

This is more useful to me that always using the same bucket name, because it's
not always easy to delete a bucket - if one sets legal hold or retention
policy on a bucket, RGW might not allow it to be deleted. With the dynamic
bucket creation, each script uses a different bucket name and the problem
never arises.

I use the letter suffix to indicate what 'type' of bucket I'm creating. No
suffix means a regular bucket (without versioning). 'v' indicates a bucket
with versioning enabled. 'l' indicates a bucket with Object Lock enabled.

### <a name='Testingusingthelocalclient'></a>Testing using the local client

```sh

# Get help. Note that you can set most request fields explicitly using various
# options.
./authorizer_client.py -h

# Send a simple ping (easy test).
./authorizer_client.py -v ping

# Authorize a get-object request (expect success with bucket1).
./authorizer_client.py -v authorize -b bucket1 -k foo -u testid1 \
	-o GetObject

# Authorize a get-object request (expect failure with bucket2).
./authorizer_client.py -v authorize -b bucket2 -k foo -u testid1 \
	-o GetObject

# Authorize a get-object request (expect an 'extra data required' answer with bucket2).
./authorizer_client.py -v authorize -b bucket3 -k foo -u testid1 \
	-o GetObject
	
# Authorize in one question get-object, get-object-legal-hold and 
# get-object-retention (this is a real thing).
./authorizer_client.py -v authorize -b bucket1 -k foo -u testid1 \
    -o GetObject -o GetObjectLegalHold -o GetObjectRetention

# Authorize a get-object request, providing object tags.
./authorizer_client.py -v authorize -b bucket3 -k foo -u testid1 \
	-o GetObject --object-tag tagkey=tagvalue

# Authorize a list-bucket request, providing query parameters.
./authorizer_client.py -v authorize -b bucket1 -u testid \
    -o ListBucket --param "prefix=/foo"
	
# Authorize a put-object request, providing a (random) x-amz- header.
./authorizer_client.py -v authorize -b bucket1 -u testid \
    -o PutObject --amz "x-amz-foo=bar"

# I suspect you're getting the idea by now.
```

## <a name='NotinuseortestedTLSmode'></a>(Not in use or tested) TLS mode

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
  -v ping

```

