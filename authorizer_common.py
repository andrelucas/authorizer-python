#!/usr/bin/env python3

from authorizer.v1 import authorizer_pb2_grpc
from authorizer.v1 import authorizer_pb2

from google.protobuf.json_format import MessageToJson

op_enum = authorizer_pb2.S3Opcode

opcode_to_enum = {
    "GetObject": op_enum.S3_OPCODE_GET_OBJECT,
    "GetObjectVersion": op_enum.S3_OPCODE_GET_OBJECT_VERSION,
    "PutObject": op_enum.S3_OPCODE_PUT_OBJECT,
    "GetObjectAcl": op_enum.S3_OPCODE_GET_OBJECT_ACL,
    "GetObjectVersionAcl": op_enum.S3_OPCODE_GET_OBJECT_VERSION_ACL,
    "PutObjectAcl": op_enum.S3_OPCODE_PUT_OBJECT_ACL,
    "PutObjectVersionAcl": op_enum.S3_OPCODE_PUT_OBJECT_VERSION_ACL,
    "DeleteObject": op_enum.S3_OPCODE_DELETE_OBJECT,
    "DeleteObjectVersion": op_enum.S3_OPCODE_DELETE_OBJECT_VERSION,
    "ListMultipartUploadParts": op_enum.S3_OPCODE_LIST_MULTIPART_UPLOAD_PARTS,
    "AbortMultipartUpload": op_enum.S3_OPCODE_ABORT_MULTIPART_UPLOAD,
    "GetObjectTorrent": op_enum.S3_OPCODE_GET_OBJECT_TORRENT,
    "GetObjectVersionTorrent": op_enum.S3_OPCODE_GET_OBJECT_VERSION_TORRENT,
    "RestoreObject": op_enum.S3_OPCODE_RESTORE_OBJECT,
    "CreateBucket": op_enum.S3_OPCODE_CREATE_BUCKET,
    "DeleteBucket": op_enum.S3_OPCODE_DELETE_BUCKET,
    "ListBucket": op_enum.S3_OPCODE_LIST_BUCKET,
    "ListBucketVersions": op_enum.S3_OPCODE_LIST_BUCKET_VERSIONS,
    "ListAllMyBuckets": op_enum.S3_OPCODE_LIST_ALL_MY_BUCKETS,
    "ListBucketMultipartUploads": op_enum.S3_OPCODE_LIST_BUCKET_MULTIPART_UPLOADS,
    "GetAccelerateConfiguration": op_enum.S3_OPCODE_GET_ACCELERATE_CONFIGURATION,
    "PutAccelerateConfiguration": op_enum.S3_OPCODE_PUT_ACCELERATE_CONFIGURATION,
    "GetBucketAcl": op_enum.S3_OPCODE_GET_BUCKET_ACL,
    "PutBucketAcl": op_enum.S3_OPCODE_PUT_BUCKET_ACL,
    "GetBucketCORS": op_enum.S3_OPCODE_GET_BUCKET_CORS,
    "PutBucketCORS": op_enum.S3_OPCODE_PUT_BUCKET_CORS,
    "GetBucketVersioning": op_enum.S3_OPCODE_GET_BUCKET_VERSIONING,
    "PutBucketVersioning": op_enum.S3_OPCODE_PUT_BUCKET_VERSIONING,
    "GetBucketRequestPayment": op_enum.S3_OPCODE_GET_BUCKET_REQUEST_PAYMENT,
    "PutBucketRequestPayment": op_enum.S3_OPCODE_PUT_BUCKET_REQUEST_PAYMENT,
    "GetBucketLocation": op_enum.S3_OPCODE_GET_BUCKET_LOCATION,
    "GetBucketPolicy": op_enum.S3_OPCODE_GET_BUCKET_POLICY,
    "DeleteBucketPolicy": op_enum.S3_OPCODE_DELETE_BUCKET_POLICY,
    "PutBucketPolicy": op_enum.S3_OPCODE_PUT_BUCKET_POLICY,
    "GetBucketNotification": op_enum.S3_OPCODE_GET_BUCKET_NOTIFICATION,
    "PutBucketNotification": op_enum.S3_OPCODE_PUT_BUCKET_NOTIFICATION,
    "GetBucketLogging": op_enum.S3_OPCODE_GET_BUCKET_LOGGING,
    "PutBucketLogging": op_enum.S3_OPCODE_PUT_BUCKET_LOGGING,
    "GetBucketTagging": op_enum.S3_OPCODE_GET_BUCKET_TAGGING,
    "PutBucketTagging": op_enum.S3_OPCODE_PUT_BUCKET_TAGGING,
    "GetBucketWebsite": op_enum.S3_OPCODE_GET_BUCKET_WEBSITE,
    "PutBucketWebsite": op_enum.S3_OPCODE_PUT_BUCKET_WEBSITE,
    "DeleteBucketWebsite": op_enum.S3_OPCODE_DELETE_BUCKET_WEBSITE,
    "GetLifecycleConfiguration": op_enum.S3_OPCODE_GET_LIFECYCLE_CONFIGURATION,
    "PutLifecycleConfiguration": op_enum.S3_OPCODE_PUT_LIFECYCLE_CONFIGURATION,
    "PutReplicationConfiguration": op_enum.S3_OPCODE_PUT_REPLICATION_CONFIGURATION,
    "GetReplicationConfiguration": op_enum.S3_OPCODE_GET_REPLICATION_CONFIGURATION,
    "DeleteReplicationConfiguration": op_enum.S3_OPCODE_DELETE_REPLICATION_CONFIGURATION,
    "GetObjectTagging": op_enum.S3_OPCODE_GET_OBJECT_TAGGING,
    "PutObjectTagging": op_enum.S3_OPCODE_PUT_OBJECT_TAGGING,
    "DeleteObjectTagging": op_enum.S3_OPCODE_DELETE_OBJECT_TAGGING,
    "GetObjectVersionTagging": op_enum.S3_OPCODE_GET_OBJECT_VERSION_TAGGING,
    "PutObjectVersionTagging": op_enum.S3_OPCODE_PUT_OBJECT_VERSION_TAGGING,
    "DeleteObjectVersionTagging": op_enum.S3_OPCODE_DELETE_OBJECT_VERSION_TAGGING,
    "PutBucketObjectLockConfiguration": op_enum.S3_OPCODE_PUT_BUCKET_OBJECT_LOCK_CONFIGURATION,
    "GetBucketObjectLockConfiguration": op_enum.S3_OPCODE_GET_BUCKET_OBJECT_LOCK_CONFIGURATION,
    "PutObjectRetention": op_enum.S3_OPCODE_PUT_OBJECT_RETENTION,
    "GetObjectRetention": op_enum.S3_OPCODE_GET_OBJECT_RETENTION,
    "PutObjectLegalHold": op_enum.S3_OPCODE_PUT_OBJECT_LEGAL_HOLD,
    "GetObjectLegalHold": op_enum.S3_OPCODE_GET_OBJECT_LEGAL_HOLD,
    "BypassGovernanceRetention": op_enum.S3_OPCODE_BYPASS_GOVERNANCE_RETENTION,
    "GetBucketPolicyStatus": op_enum.S3_OPCODE_GET_BUCKET_POLICY_STATUS,
    "PutPublicAccessBlock": op_enum.S3_OPCODE_PUT_PUBLIC_ACCESS_BLOCK,
    "GetPublicAccessBlock": op_enum.S3_OPCODE_GET_PUBLIC_ACCESS_BLOCK,
    "DeletePublicAccessBlock": op_enum.S3_OPCODE_DELETE_PUBLIC_ACCESS_BLOCK,
    "GetBucketPublicAccessBlock": op_enum.S3_OPCODE_GET_BUCKET_PUBLIC_ACCESS_BLOCK,
    "PutBucketPublicAccessBlock": op_enum.S3_OPCODE_PUT_BUCKET_PUBLIC_ACCESS_BLOCK,
    "DeleteBucketPublicAccessBlock": op_enum.S3_OPCODE_DELETE_BUCKET_PUBLIC_ACCESS_BLOCK,
    "GetBucketEncryption": op_enum.S3_OPCODE_GET_BUCKET_ENCRYPTION,
    "PutBucketEncryption": op_enum.S3_OPCODE_PUT_BUCKET_ENCRYPTION,
}


def fmt_common(common):
    return MessageToJson(common, indent=None)


def fmt_authorize_request(req: authorizer_pb2.AuthorizeV2Request):
    return MessageToJson(req, indent=None)


def fmt_authorize_response(response: authorizer_pb2.AuthorizeV2Response) -> str:
    return MessageToJson(response, indent=None)
