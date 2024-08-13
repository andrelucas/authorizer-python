#!/usr/bin/env python3
"""
Minimal HTTP server implementing the Authorizer protocol.

Usage::
    ./authorizer_server.py [-v] [<port>]
"""

import argparse
import base64
import coloredlogs
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
import json

from authorizer.v1 import authorizer_pb2_grpc
from authorizer.v1 import authorizer_pb2

from authorizer_common import *


class PolicyEvaluationFailedException(Exception):
    def __init__(self, message: str):
        self.message = message

    def __str__(self) -> str:
        return f"PolicyEvaluationFailedException(message={self.message})"


class ExtraDataRequiredException(Exception):
    def __init__(self, object_key_tags: bool):
        self.object_key_tags = object_key_tags

    def __str__(self) -> str:
        return f"ExtraDataRequiredException(object_key_tags={self.object_key_tags})"


def evaluate_policy(policy, question, bucket=None, object_key=None) -> bool:
    """
    Evaluate the policy against the request, given the bucket and object key.

    XXX policies are super simple for now.

    True means 'allow', False means 'deny'.
    """
    logging.debug(
        f"Evaluate: '{policy}' " f"bucket: {bucket}, object_key: {object_key}"
    )

    p = json.loads(policy)

    if p["action"] == "deny":
        logging.error("Explicit deny")
        return False

    if p["action"] == "allow":
        if "require" in p:
            # This is to test that the client doesn't get stuck in a loop.
            if "extraDataLoop" in p:
                logging.warning("Generating extra data loop")
                raise ExtraDataRequiredException(True)

            has_edp = question.HasField("extra_data_provided")
            require_object_key_tags = False
            req_fail = False
            edp = None

            if has_edp:
                edp = question.extra_data_provided
                logging.debug(
                    f"Has extra data provided: {fmt_extra_data_specification(edp)}"
                )

            # Check for object key tags, the only currently-supported extra
            # data.
            if "objectTags" in p["require"]:
                if question.object_key_name == "":
                    logging.info(
                        "Not insisting on object key tags for request with no object key"
                    )
                else:
                    require_object_key_tags = True
                    if not has_edp or not edp.object_key_tags:
                        logging.warn("Object key tags required but not present")
                        req_fail = True

            if req_fail:
                raise ExtraDataRequiredException(require_object_key_tags)

        logging.info("Explicit allow")
        return True

    logging.error("Default deny")
    return False


class ObjectKey:
    def __init__(self, key: str, value: str, tags: dict):
        self.key = key
        self.value = value
        self.tags = tags

    def __repr__(self) -> str:
        return f"ObjectKey(key={self.key}, tags={self.tags})"


class Bucket:
    def __init__(self, name: str, tags: dict, policy=None):
        self.name = name
        self.tags = tags
        self.objects = {}
        self.policy = policy

    def add_object(self, object_key):
        self.objects[object_key.key] = object_key

    def get_object(self, key) -> ObjectKey:
        if key in self.objects:
            return self.objects[key]
        return None

    def delete_object(self, key) -> None:
        if key in self.objects:
            del self.objects[key]

    def __repr__(self) -> str:
        return (
            f"Bucket(name={self.name}, tags={self.tags}, "
            f"policy='{self.policy}', objects={self.objects})"
        )


class Store:
    def __init__(self):
        self.buckets = {}

    def add_bucket(self, bucket: Bucket):
        self.buckets[bucket.name] = bucket

    def get_bucket(self, name: str):
        if name in self.buckets:
            return self.buckets[name]
        return None

    def __str__(self) -> str:
        return f"Store(buckets={self.buckets})"

    def authorize(self, question):
        """
        Authorize the question against this store. Return the answer message.
        """
        allow = False

        bucket = None
        bucket_name = None
        object_key = None
        object_key_name = None

        answer = authorizer_pb2.AuthorizeV2Answer()
        answer.common.timestamp.GetCurrentTime()
        answer.common.authorization_id = question.common.authorization_id

        # Not all requests have a bucket name.
        if question.bucket_name != "":
            bucket_name = question.bucket_name
            bucket = self.get_bucket(question.bucket_name)
            if bucket is None:
                logging.error(f"Bucket '{question.bucket_name}' not found")
                answer.code = authorizer_pb2.AuthorizationResultCode.AUTHZ_RESULT_DENY

            # Not all requests that have a bucket have an object key. If the
            # key doesn't exist, just create it (for now).
            if question.object_key_name != "":
                object_key_name = question.object_key_name
                if not object_key_name in bucket.objects:
                    logging.debug(
                        f"Creating object key '{object_key_name}' in bucket '{bucket_name}'"
                    )
                    bucket.add_object(ObjectKey(object_key_name, "value1", {}))
                object_key = bucket.get_object(object_key_name)
                # if object_key is None:
                #     logging.error(
                #         f"Object key '{object_key_name}' not found in bucket '{bucket_name}'"
                #     )
                #     raise AccessDeniedException(
                #         f"Object key '{request.object_key_name}' not found in "
                #         f"bucket '{request.bucket_name}'"
                #     )

        if bucket is None and object_key is None:
            # XXX just allow it for now.
            logging.debug("No bucket or object key, allowing")
            answer.code = authorizer_pb2.AuthorizationResultCode.AUTHZ_RESULT_ALLOW
            return answer

        if bucket is not None:
            policy = bucket.policy
            if policy is None:
                logging.debug(f"Applying default-allow policy for bucket {bucket_name}")
                allow = True
            else:
                try:
                    allow = evaluate_policy(
                        policy, question, bucket=bucket, object_key=object_key
                    )
                except ExtraDataRequiredException as e:
                    answer.code = (
                        authorizer_pb2.AuthorizationResultCode.AUTHZ_RESULT_EXTRA_DATA_REQUIRED
                    )
                    answer.extra_data_required.object_key_tags = e.object_key_tags
                    return answer

        if allow:
            answer.code = authorizer_pb2.AuthorizationResultCode.AUTHZ_RESULT_ALLOW
        else:
            answer.code = authorizer_pb2.AuthorizationResultCode.AUTHZ_RESULT_DENY

        return answer


def load_store(store):

    always_allow = {
        "action": "allow",
    }

    always_deny = {
        "action": "deny",
    }

    allow_with_object_tags = {
        "action": "allow",
        "require": [
            "objectTags",
        ],
    }

    extra_data_loop = {
        "action": "allow",
        "require": [
            "objectTags",
        ],
        "extraDataLoop": True,
    }

    policies = [always_allow, allow_with_object_tags, always_deny, extra_data_loop ]

    for n, p in enumerate(policies, start=1):
        bname = f"bucket{n}"
        logging.debug(f"Bucket {bname} policy: {p}")
        logging.debug(f"Bucket {bname} regular")
        b = Bucket(bname, {}, json.dumps(p))
        store.add_bucket(b)
        b.add_object(ObjectKey("objectkey1", "value1", {}))

        bname = f"bucket{n}v"
        logging.debug(f"Bucket {bname} versioned")
        bv = Bucket(bname, {}, json.dumps(p))
        store.add_bucket(bv)
        bv.add_object(ObjectKey("objectkey1", "value1", {}))

        bname = f"bucket{n}l"
        logging.debug(f"Bucket {bname} object lock")
        bl = Bucket(bname, {}, json.dumps(p))
        store.add_bucket(bl)
        bl.add_object(ObjectKey("objectkey1", "value1", {}))

        bname = f"bucket{n}vl"
        logging.debug(f"Bucket {bname} versioned and object lock")
        bvl = Bucket(bname, {}, json.dumps(p))
        store.add_bucket(bvl)
        bvl.add_object(ObjectKey("objectkey1", "value1", {}))

    logging.debug(f"Store: {store}")


def authz_internal_error_status(e: Exception):
    """
    Return a google.rpc.status_pb2.Status object for the given exception.
    """
    # detail = any_pb2.Any()
    # detail.Pack(
    #     authorizer_pb2.AuthorizationErrorDetails(
    #         code=authorizer_pb2.AuthorizationResultCode.AUTHZ_RESULT_INTERNAL_ERROR,
    #         internal_error=authorizer_pb2.InternalErrorDetails(message=str(e)),
    #     )
    # )
    return status_pb2.Status(code=code_pb2.INTERNAL, message="Internal error")


class AuthorizerServer(authorizer_pb2_grpc.AuthorizerServiceServicer):

    def __init__(self):
        self.store = Store()
        load_store(self.store)
        super().__init__()

    def Header(self, request):
        logging.info("-------------")
        ids = []
        for question in request.questions:
            ids.append(question.common.authorization_id)

        logging.info(f"New request: ids{ids}")

    # Note: Authorize() (the original service) not implemented here.

    def Ping(self, request, context):
        self.Header(request)
        logging.debug(f"Ping request: {fmt_common(request.common)}")
        response = authorizer_pb2.PingResponse()
        response.common.timestamp.GetCurrentTime()
        response.common.authorization_id = request.common.authorization_id
        logging.debug(f"Ping response: {fmt_common(response.common)}")
        return response

    def AuthorizeV2(self, request, context):
        self.Header(request)
        logging.debug(f"Request: {fmt_authorize_request(request)}")

        try:
            response = authorizer_pb2.AuthorizeV2Response()

            for n, question in enumerate(request.questions, start=1):
                logging.info(f"Question {n}: {fmt_question(question)}")
                answer = self.store.authorize(question)
                logging.info(f"Answer {n}: {fmt_answer(answer)}")
                response.answers.append(answer)

            logging.debug(f"Response: {fmt_authorize_response(response)}")
            return response

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
        coloredlogs.install(level=logging.DEBUG, isatty=True)
    else:
        coloredlogs.install(level=logging.INFO, isatty=True)

    if args.tls:
        if not args.server_cert:
            logging.error("TLS requires a server certificate")
            sys.exit(1)
        if not args.server_key:
            logging.error("TLS requires a server key")
            sys.exit(1)

    run(args)
