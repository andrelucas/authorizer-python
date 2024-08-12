#!/usr/bin/env python3
"""
Simple test client for the Authorizer gRPC service.
"""

import argparse
import base64
import coloredlogs
from google.rpc import code_pb2
from google.rpc import error_details_pb2
from google.rpc import status_pb2
from google.protobuf.json_format import MessageToJson
from google.protobuf.timestamp_pb2 import Timestamp
import grpc
from grpc_status import rpc_status
import logging
import os
import sys

from authorizer.v1 import authorizer_pb2_grpc
from authorizer.v1 import authorizer_pb2

from authorizer_common import (
    opcode_to_enum,
    fmt_authorize_request,
    fmt_authorize_response,
    fmt_common,
)


def ping(stub, args):
    """
    Ping the server.
    """
    try:
        question = authorizer_pb2.PingRequest()
        question.common.timestamp.GetCurrentTime()
        question.common.authorization_id = args.id
        logging.debug(f"Sending Ping(id={args.id})")
        logging.debug(f"Request: {fmt_common(question.common)}")
        response = stub.Ping(question)
        logging.debug(f"Response: {fmt_common(response.common)}")
        return response.common.authorization_id.encode() == args.id

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


def pack_authorize_request(req, args):
    """
    Pack the AuthorizeRequest with the args.
    """
    for op in args.opcode:
        question = req.questions.add()
        question.common.timestamp.GetCurrentTime()
        question.common.authorization_id = args.id
        question.bucket_name = args.bucket
        question.object_key_name = args.object_key
        question.opcode = opcode_to_enum[op]  # We've already checked this is valid.
        question.canonical_user_id = args.canonical_user_id
        question.user_arn = args.user_arn
        if args.assuming_user_arn is not None:
            question.assuming_user_arn = args.assuming_user_arn
        question.account_arn = args.account_arn

        if args.object_tag:  # Allow for more than one extra data item in the future.
            # At least one extra data item is set.
            if args.object_tag:
                question.extra_data_provided.object_key_tags = True
                for tag in args.object_tag:
                    key, value = tag.split("=", 1)
                    # iamkey = "s3:ResourceTag/" + key
                    # question.environment[iamkey].key.append(value)
                    question.extra_data.object_key_tags[key] = value

        for env in args.environment:
            key, value = env.split("=", 1)
            question.environment[key].key.append(value)

    return req


def authorize_v2(stub, args):
    """
    Authorize the server.
    """
    try:
        req = authorizer_pb2.AuthorizeV2Request()
        pack_authorize_request(req, args)
        logging.debug(fmt_authorize_request(req))
        response = stub.AuthorizeV2(req)
        logging.debug(fmt_authorize_response(response))
        # if response.common.authorization_id.encode() != args.id:
        #     logging.error(
        #         f"Authorization ID mismatch: {response.common.authorization_id} != {args.id}"
        #     )
        #     return False

        success = True
        extra_data_required = False

        for n, answer in enumerate(response.answers, start=1):
            codestr = authorizer_pb2.AuthorizationResultCode.DESCRIPTOR.values_by_number[answer.code].name
            logging.debug(f"Answer {n}: {codestr}: {fmt_common(answer.common)}")

            if answer.code != authorizer_pb2.AUTHZ_RESULT_ALLOW:
                success = False
            if answer.code == authorizer_pb2.AUTHZ_RESULT_EXTRA_DATA_REQUIRED:
                extra_data_required = True
            # if answer.answer.result_code != authorizer_pb2.AuthorizationResultCode.AUTHZ_OK:
            #     logging.error(
            #         f"Authorization failed: {authorizer_pb2.AuthorizationResultCode.DESCRIPTOR.values_by_number[answer.answer.result_code].name}"
            #     )
            #     return False

        if success:
            logging.debug("Authorization successful")
            return True
        else:
            logging.error("Authorization failed")
            return False

    except grpc.RpcError as e:
        # Unpack the error.
        status = rpc_status.from_call(e)
        if status is None:
            logging.error(f"RPC failed: {e}")
        else:
            logging.error(f"RPC failed: code={status.code} message='{status.message}'")
            # for detail in status.details:
            #     # Unpack the ANY if it's a specific type.
            #     if detail.Is(authorizer_pb2.AuthorizationErrorDetails.DESCRIPTOR):
            #         error_details = authorizer_pb2.AuthorizationErrorDetails()
            #         detail.Unpack(error_details)
            #         codestr = authorizer_pb2.AuthorizationResultCode.DESCRIPTOR.values_by_number[error_details.code].name
            #         logging.error(
            #             f"AuthorizationErrorDetails: code={codestr} edr={MessageToJson(error_details.extra_data_required, indent=None)}"
            #         )

        return False


def issue(channel, args):
    """
    Issue the RPC. Factored out so we can use different types of channel.
    """
    stub = authorizer_pb2_grpc.AuthorizerServiceStub(channel)

    if args.command == "ping":
        return ping(stub, args)
    elif args.command == "authorize":
        return authorize_v2(stub, args)
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

    p.add_argument("--id", help="authorization_id field override (default is random)")
    p.add_argument("-b", "--bucket", help="bucket to authorize", default="")
    p.add_argument("-k", "--object-key", help="object key to authorize", default="")
    p.add_argument("-o", "--opcode", help="opcode/action to authorize", action="append")
    p.add_argument(
        "-e",
        "--environment",
        help="IAM environment entry in the form key=value",
        action="append",
    )
    p.add_argument(
        "-u", "--canonical-user-id", help="canonical user ID to authorize", default=""
    )
    p.add_argument("--user-arn", help="user ARN to authorize", default="")
    p.add_argument(
        "--assuming-user-arn", help="assuming user ARN to authorize", default=None
    )
    p.add_argument("--account-arn", help="account ARN to authorize", default="")

    p.add_argument("--object-tag", help="set an object tag (k=v)", action="append")

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
        coloredlogs.install(level=logging.DEBUG)
    else:
        coloredlogs.install(level=logging.INFO)

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

    if args.command == "authorize":
        if not args.opcode:
            logging.error("Authorize requires an opcode")
            sys.exit(2)
        for op in args.opcode:
            if not op in opcode_to_enum:
                logging.error(f"Unknown opcode '{op}'")
                sys.exit(2)
        # args.opcode_enum = opcode_to_enum[args.opcode]

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
