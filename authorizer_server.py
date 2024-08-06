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
from google.protobuf.json_format import MessageToJson
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

from authorizer_common import fmt_authorize_request, fmt_authorize_response, fmt_common


class AuthzRequest:
    def __init__(self, request):
        """
        Create an authorization request from the incoming gRPC
        AuthorizeRequest message.
        """
        self.canonical_user_id = request.canonical_user_id
        self.user_arn = request.user_arn
        if request.HasField("assuming_user_arn"):
            self.assuming_user_arn = request.assuming_user_arn
        else:
            self.assuming_user_arn = None
        self.account_arn = request.account_arn
        self.opcode = request.opcode
        self.bucket_name = request.bucket_name
        self.object_key_name = request.object_key_name
        # XXX extra data

    def __str__(self):
        return f"""AuthzRequest(canonical_user_id={self.canonical_user_id},
          user={self.user_arn}, assuming_user_arn={self.assuming_user_arn},
          account_arn={self.account_arn},
          opcode={self.opcode}, bucket={self.bucket_name},
          object_key_name={self.object_key_name})"""


class ExtraDataRequiredException(Exception):
    def __init__(self, bucket_tags: bool, object_key_tags: bool):
        self.bucket_tags = bucket_tags
        self.object_key_tags = object_key_tags

    def __str__(self) -> str:
        return f"ExtraDataRequiredException(bucket_tags={self.bucket_tags}, object_key_tags={self.object_key_tags})"


def authz_extra_data_required_status(bucket_tags: bool, object_key_tags: bool):
    """
    Return a google.rpc.status_pb2.Status object indicating that extra data is
    required.
    """
    detail = any_pb2.Any()
    edr = authorizer_pb2.ExtraDataSpecification(
        bucket_tags=bucket_tags, object_key_tags=object_key_tags
    )
    detail.Pack(
        authorizer_pb2.AuthorizationErrorDetails(
            code=authorizer_pb2.AuthorizationResultCode.AUTHZ_RESULT_EXTRA_DATA_REQUIRED,
            extra_data_required=edr,
        )
    )
    return status_pb2.Status(
        code=code_pb2.INTERNAL, message="Extra data required", details=[detail]
    )


def authz_internal_error_status(e: Exception):
    """
    Return a google.rpc.status_pb2.Status object for the given exception.
    """
    status = status_pb2.Status()
    status.code = code_pb2.INTERNAL
    status.message = str(e)
    return status


class AuthorizerServer(authorizer_pb2_grpc.AuthorizerServiceServicer):

    # Note: Authorize() (the original service) not implemented here.

    def Ping(self, request, context):
        logging.debug(f"Ping request: {fmt_common(request.common)}")
        response = authorizer_pb2.PingResponse()
        response.common.timestamp.GetCurrentTime()
        response.common.authorization_id = request.common.authorization_id
        logging.debug(f"Ping response: {fmt_common(response.common)}")
        return response

    def AuthorizeV2(self, request, context):
        logging.debug(f"Request: {fmt_authorize_request(request)}")

        try:
            response = authorizer_pb2.AuthorizeV2Response()
            response.common.timestamp.GetCurrentTime()
            response.common.authorization_id = request.common.authorization_id

            try:
                authreq = AuthzRequest(request)

            except Exception as e:
                logging.error(f"Failed to parse request into AuthzRequest: {e}")
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid request")

            # XXX actually authorize...
            # logging.debug("Raising fake ExtraDataRequiredException")
            # raise ExtraDataRequiredException(True, True)
            logging.debug(f"Response: {fmt_authorize_response(response)}")
            return response

        except ExtraDataRequiredException as e:
            context.abort_with_status(
                rpc_status.to_status(authz_extra_data_required_status(e.bucket_tags, e.object_key_tags))
            )

        except Exception as e:
            logging.error(f"Failed to handle request: {e}")
            context.abort_with_status(
                rpc_status.to_status(authz_internal_error_status(e))
            )


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
        authorizer_pb2_grpc.add_AuthorizerServiceServicer_to_server(
            AuthorizerServer(), server
        )

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
