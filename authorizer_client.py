#!/usr/bin/env python3
"""
Simple test client for the Authorizer gRPC service.
"""

import argparse
import base64
from google.rpc import code_pb2
from google.rpc import error_details_pb2
from google.rpc import status_pb2
from google.protobuf.timestamp_pb2 import Timestamp
import grpc
from grpc_status import rpc_status
import logging
import os
import sys

from authorizer.v1 import authorizer_pb2_grpc as authorizer_pb2_grpc
from authorizer.v1 import authorizer_pb2 as authorizer_pb2


def dump_common(desc, common):
    """
    Dump the common fields to the log.
    """
    tsiso = common.timestamp.ToDatetime().isoformat()
    logging.debug(f"{desc} ts=({tsiso}), id={common.authorization_id}")


def ping(stub, args):
    """
    Ping the server.
    """
    try:
        req = authorizer_pb2.PingRequest()
        req.common.timestamp.GetCurrentTime()
        req.common.authorization_id = args.id
        logging.debug(f"Sending Ping(id={args.id})")
        dump_common("Request", req.common)
        response = stub.Ping(req)
        dump_common("Response", response.common)
        return response.common.authorization_id == args.id

    except grpc.RpcError as e:
        # Unpack the error.
        status = rpc_status.from_call(e)
        if status is None:
            logging.error(f"RPC failed: {e}")
        else:
            logging.error(
                f"RPC failed: error={e} code={status.code} message='{status.details}'"
            )
            for detail in status.details:
                # Unpack the ANY if it's a specific type.
                if detail.Is(error_details_pb2.DebugInfo.DESCRIPTOR):
                    debug_info = error_details_pb2.DebugInfo()
                    detail.Unpack(debug_info)
                    logging.error(f"DebugInfo: {debug_info}")

        return False

def authorize(stub, args):
    """
    Authorize the server.
    """
    try:
        logging.debug(f"Sending Authorize({args.id})")
        req = authorizer_pb2.AuthorizeRequest()
        req.common.timestamp.GetCurrentTime()
        req.common.authorization_id = args.id
        dump_common("Request", req.common)
        # XXX implement!
        response = stub.Authorize(req)
        dump_common("Response", response.common)
        return True # XXX

    except grpc.RpcError as e:
        # Unpack the error.
        status = rpc_status.from_call(e)
        if status is None:
            logging.error(f"RPC failed: {e}")
        else:
            logging.error(
                f"RPC failed: error={e} code={status.code} message='{status.details}'"
            )
            for detail in status.details:
                # Unpack the ANY if it's a specific type.
                if detail.Is(error_details_pb2.DebugInfo.DESCRIPTOR):
                    debug_info = error_details_pb2.DebugInfo()
                    detail.Unpack(debug_info)
                    logging.error(f"DebugInfo: {debug_info}")

        return False


def issue(channel, args):
    """
    Issue the RPC. Factored out so we can use different types of channel.
    """
    stub = authorizer_pb2_grpc.AuthorizerServiceStub(channel)

    if args.command == "ping":
        return ping(stub, args)
    elif args.command == "authorize":
        return authorize(stub, args)
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
    p.add_argument("--id", help="authorization_id field override (default is random)")

    p.add_argument(
        "-t", "--tls", help="connect to the server using TLS", action="store_true"
    )
    p.add_argument("--uri", help="server uri (will override address and port!)")
    p.add_argument("-a", "--address", help="server address", default="127.0.0.1")
    p.add_argument("-p", "--port", type=int, default=8003, help="server listen port")
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

    # The user can override the authorization_id field, but if not provided,
    # generate a random one.
    if not args.id:
        args.id = base64.b64encode(os.urandom(16))

    if args.tls:
        root_crt = _load_credential_from_file(args.ca_cert)
        channel_credential = grpc.ssl_channel_credentials(root_crt)
        with grpc.secure_channel(server_address, channel_credential) as channel:
            success = issue(channel, args)
    else:
        with grpc.insecure_channel(server_address) as channel:
            success = issue(channel, args)

    if success:
        logging.info("Success")
        sys.exit(0)
    else:
        logging.error("RPC failed")
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
