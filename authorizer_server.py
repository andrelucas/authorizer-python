#!/usr/bin/env python3
"""
Minimal HTTP server implementing the Authorizer protocol.

Usage::
    ./authorizer_server.py [-v] [<port>]
"""

import argparse
import base64
from concurrent import futures
from google.protobuf import any_pb2
from google.rpc import code_pb2
from google.rpc import error_details_pb2
from google.rpc import status_pb2
import grpc
from grpc_status import rpc_status
import logging
import re
import os
import sys

from authorizer.v1 import authorizer_pb2_grpc
from authorizer.v1 import authorizer_pb2

def fmt_common(desc, common):
    """
    Dump the common fields to the log.
    """
    tsiso = common.timestamp.ToDatetime().isoformat()
    return f"{desc} ts=({tsiso}), id={common.authorization_id}"

class AuthorizerServer(authorizer_pb2_grpc.AuthorizerServiceServicer):

    def Ping(self, request, context):
        logging.debug(f"Received Ping({request})")
        logging.debug(fmt_common("Ping Request", request.common))
        response = authorizer_pb2.PingResponse()
        response.common.timestamp.GetCurrentTime()
        response.common.authorization_id = request.common.authorization_id
        logging.debug(fmt_common("Ping Response", response.common))
        return response

    def Authorize(self, request, context):
        logging.debug(f"Received Authorize({request})")
        logging.debug(fmt_common("Authorize Request", request.common))
        response = authorizer_pb2.AuthorizeResponse()
        response.common.timestamp.GetCurrentTime()
        response.common.authorization_id = request.common.authorization_id
        logging.debug(fmt_common("Authorize Response", response.common))
        return response

def _load_credential_from_file(filepath):
    """https://github.com/grpc/grpc/blob/master/examples/python/auth/_credentials.py"""
    real_path = os.path.join(os.path.dirname(__file__), filepath)
    with open(real_path, "rb") as f:
        return f.read()


def run(args):
    server_address = f"127.0.0.1:{args.port}"
    logging.info("Starting gRPC service...\n")
    try:
        server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=10),
            options=(
                ("grpc.so_reuseport", 0),
            ),  # This apparently helps detect port reuse - see https://github.com/grpc/grpc/issues/16920
        )
        authorizer_pb2_grpc.add_AuthorizerServiceServicer_to_server(AuthorizerServer(), server)

        if args.tls:
            server_crt = _load_credential_from_file(args.server_cert)
            server_key = _load_credential_from_file(args.server_key)
            server_credentials = grpc.ssl_server_credentials(
                (
                    (
                        server_key,
                        server_crt,
                    ),
                )
            )
            server.add_secure_port(server_address, server_credentials)

        else:
            server.add_insecure_port(server_address)

        server.start()
        logging.info(f"Server started, listening on {server_address}")
        server.wait_for_termination()
    except KeyboardInterrupt:
        pass
    logging.info("Stopping gRPC server...\n")


if __name__ == "__main__":
    from sys import argv

    p = argparse.ArgumentParser(description="Authorizer gRPC server")
    p.add_argument("port", type=int, help="Listen port", nargs="?", default=8003)
    p.add_argument(
        "-t", "--tls", help="connect to the server using TLS", action="store_true"
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    ptls = p.add_argument_group("TLS arguments")
    ptls.add_argument("--ca-cert", help="CA certificate file (NOT YET USED)")
    ptls.add_argument("--server-cert", help="client certificate file")
    ptls.add_argument("--server-key", help="client key file")

    args = p.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.tls:
        if not args.server_cert:
            logging.error("TLS requires a server certificate")
            sys.exit(1)
        if not args.server_key:
            logging.error("TLS requires a server key")
            sys.exit(1)

    run(args)
