#!/usr/bin/env python3
"""
Simple test client for the Authorizer gRPC service.
"""

import argparse
import base64
from google.rpc import code_pb2
from google.rpc import error_details_pb2
from google.rpc import status_pb2
import grpc
from grpc_status import rpc_status
import logging
import os
import sys

from authorizer.v1 import authorizer_pb2_grpc as authorizer_pb2_grpc
from authorizer.v1 import authorizer_pb2 as authorizer_pb2


def ping(stub, args):
    """
    Ping the server.
    """
    logging.debug(f"Sending Ping(args.message={args.message})")
    req = authorizer_pb2.PingRequest()
    req.message = args.message
    response = stub.Ping(req)
    logging.info(f"Response: {response.message}")


def authorize(stub, args):
    """
    Authorize the server.
    """
    # XXX implement
    logging.debug("Sending Authorize()")
    response = stub.Authorize(authorizer_pb2.AuthorizeRequest())
    logging.info(f"Response: {response}")


def issue(channel, args):
    """
    Issue the RPC. Factored out so we can use different types of channel.
    """
    stub = authorizer_pb2_grpc.AuthorizerServiceStub(channel)

    if args.command == "ping":
        success = ping(stub, args)
    elif args.command == "authorize":
        success = authorize(stub, args)
    else:
        logging.error(f"Unknown command '{args.command}'")
        sys.exit(2)


def _load_credential_from_file(filepath):
    """https://github.com/grpc/grpc/blob/master/examples/python/auth/_credentials.py"""
    real_path = os.path.join(os.path.dirname(__file__), filepath)
    with open(real_path, "rb") as f:
        return f.read()


def main(argv):
    p = argparse.ArgumentParser(description="AuthService client")
    p.add_argument("command", help="command to run", choices=["ping", "authorize"])
    # XXX command arguments
    p.add_argument("--message", help="message to send with ping", default="ping")

    p.add_argument(
        "-t", "--tls", help="connect to the server using TLS", action="store_true"
    )
    p.add_argument("--uri", help="server uri (will override address and port!)")
    p.add_argument("-a", "--address", help="server address", default="127.0.0.1")
    p.add_argument("-p", "--port", type=int, default=8002, help="server listen port")
    p.add_argument("-v", "--verbose", action="store_true")
    ptls = p.add_argument_group("TLS arguments")
    ptls.add_argument("--ca-cert", help="CA certificate file")
    ptls.add_argument("--client-cert", help="client certificate file (NOT YET USED)")
    ptls.add_argument("--client-key", help="client key file (NOT YET USED)")

    args = p.parse_args(argv)
    if not args.command:
        p.usage()
        sys.exit(1)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.tls:
        if not args.ca_cert:
            logging.error("TLS requires a CA certificate")
            sys.exit(1)

    # Set up a channel string first.
    server_address = f"dns:{args.address}:{args.port}"
    if args.uri:
        server_address = args.uri
    logging.debug(f"using server_address {server_address}")
    success = False

    if args.tls:
        root_crt = _load_credential_from_file(args.ca_cert)
        channel_credential = grpc.ssl_channel_credentials(root_crt)
        with grpc.secure_channel(server_address, channel_credential) as channel:
            issue(channel, args)
    else:
        with grpc.insecure_channel(server_address) as channel:
            issue(channel, args)

    if success:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
