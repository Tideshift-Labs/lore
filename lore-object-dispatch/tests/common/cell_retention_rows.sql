-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- Schema-only fixture. These records deliberately do not claim canonical lifecycle validity.
-- No Submit/ACK writer exists in the installed cell procedure set. Retention reads relational
-- state only; all CHECK/FK constraints remain enabled. $ID is a test-owned integer.
INSERT INTO object_store_retention.object_dispatch_requests (
 schema_revision, protocol_revision, policy_revision, provider_boundary_id,
 authenticated_cell_id, authenticated_tenant_id, logical_request_id, attempt_id,
 logical_request_uuid_unix_ms, attempt_uuid_unix_ms, canonical_descriptor_bytes,
 canonical_descriptor_fingerprint, operation_tag, consumer_context_tag, phase,
 allocation_revision, allocation_fence, admission_clock_unix_ms, deadline_unix_ms,
 allocation_hard_expiry_unix_ms, request_state_canonical_bytes, request_state_blake3,
 terminal_result_id, terminal_result_tag, terminal_result_canonical_bytes,
 terminal_result_blake3, terminal_result_size, terminal_retryability, result_disposition,
 put_payload_availability, result_payload_availability, dispatch_attempt_blake3,
 closure_committed_at_unix_ms, submit_receipt_canonical_bytes, submit_receipt_blake3,
 get_outcome_canonical_bytes, get_outcome_blake3, quota_revision, row_revision,
 state_committed_at_unix_ms, created_at_unix_ms, byte_result_handle, payload_size,
 payload_blake3, fetch_head_state, fetch_fence_generation, fetch_open_lease_count,
 fetch_head_revision, fetch_head_committed_at_unix_ms, fetch_head_canonical_bytes, fetch_head_blake3
) VALUES (
 'object-store-dispatch-authority-schema-v1','protocol-1','policy-1','boundary-1',
 'cell-1','tenant-1','$LOGICAL','$ATTEMPT',1000,1001,decode('aa','hex'),
 $DIGEST,1,1,5,'allocation-1',1,1000,2000,$EXPIRY,$RECORD,$DIGEST,
 'result-$ID',7,$RECORD,$DIGEST,33,1,3,1,3,$DIGEST,$CLOSURE,
 $RECORD,$DIGEST,$RECORD,$DIGEST,1,1,1500,1000,'result/body-$ID',33,$DIGEST,
 1,1,0,1,1500,$RECORD,$DIGEST
);
INSERT INTO object_store_retention.object_dispatch_dispatchers (
 schema_revision,dispatcher_id,lease_generation,provider_boundary_id,service_instance_id,
 dispatcher_fence,authority_revision,allocation_revision,allocation_fence,
 provider_credential_revision,state,acquired_at_unix_ms,renewed_at_unix_ms,
 expires_at_unix_ms,state_changed_at_unix_ms,canonical_record_bytes,record_blake3
) VALUES ('object-store-dispatch-authority-schema-v1','dispatcher-$ID',1,'boundary-1',
 'instance-$ID',1,1,'allocation-1',1,'cred-1',1,1000,1000,2000,1000,$RECORD,$DIGEST);
INSERT INTO object_store_retention.object_dispatch_attempts (
 schema_revision,logical_request_id,attempt_id,provider_boundary_id,provider_grant_id,
 provider_grant_fence,grant_canonical_bytes,grant_blake3,dispatcher_id,
 dispatcher_lease_generation,provider_credential_revision,attempt_state,
 provider_authority_refunded,grant_committed_at_unix_ms,attempt_revision,state_changed_at_unix_ms
) VALUES ('object-store-dispatch-authority-schema-v1','$LOGICAL','$ATTEMPT','boundary-1',
 'grant-$ID',1,$RECORD,$DIGEST,'dispatcher-$ID',1,'cred-1',1,false,1000,1,1000);
INSERT INTO object_store_retention.object_dispatch_spool_objects (
 schema_revision,spool_object_id,logical_request_id,attempt_id,provider_boundary_id,
 authenticated_cell_id,authenticated_tenant_id,bound_request_logical_request_id,
 bound_request_attempt_id,request_binding_state,payload_kind,lifecycle_state,
 terminal_result_id,boundary_blake3,boundary_token,observation_binding_blake3,
 expected_size,expected_blake3,quota_bytes,quota_rows,quota_concurrency,quota_revision,
 purge_state,canonical_record_bytes,record_blake3,spool_revision,created_at_unix_ms,
 committed_size,committed_blake3,durable_handle,ready_at_unix_ms,purged_at_unix_ms,
 release_reason,release_receipt_bytes,release_receipt_blake3
) VALUES ('object-store-dispatch-authority-schema-v1','$SPOOL','$LOGICAL','$ATTEMPT',
 'boundary-1','cell-1','tenant-1','$LOGICAL','$ATTEMPT',2,2,3,'result-$ID',
 $DIGEST,'boundary-token',$DIGEST,33,$DIGEST,33,1,1,1,3,$RECORD,$DIGEST,1,1500,
 33,$DIGEST,'result/body-$ID',1500,1600,1,$RECORD,$DIGEST);
INSERT INTO object_store_retention.object_dispatch_payload_purges (
 schema_revision,purge_id,spool_object_id,provider_boundary_id,authenticated_cell_id,
 authenticated_tenant_id,logical_request_id,attempt_id,payload_kind,terminal_result_id,
 disposition,release_reason,purge_state,purge_not_before_unix_ms,purge_fingerprint,
 canonical_intent_bytes,expected_request_state_blake3,expected_fetch_head_blake3,
 reserved_fetch_head_blake3,reserved_fetch_fence_generation,reserved_fetch_head_revision,
 reserved_open_lease_count,reservation_canonical_bytes,reservation_blake3,durable_handle,
 payload_size,payload_blake3,released_bytes,released_rows,released_concurrency,
 receipt_canonical_bytes,receipt_blake3,quota_revision,reserved_at_unix_ms,purged_at_unix_ms,purge_revision
) VALUES ('object-store-dispatch-authority-schema-v1','$PURGE','$SPOOL','boundary-1',
 'cell-1','tenant-1','$LOGICAL','$ATTEMPT',2,'result-$ID',3,1,2,1500,
 decode(lpad(to_hex($ID),64,'0'),'hex'),$RECORD,$DIGEST,$DIGEST,$DIGEST,1,1,0,
 $RECORD,$DIGEST,'result/body-$ID',33,$DIGEST,33,1,1,$RECORD,$DIGEST,1,1500,1600,1);
INSERT INTO object_store_retention.object_dispatch_fetch_leases (
 schema_revision,lease_id,provider_boundary_id,authenticated_cell_id,authenticated_tenant_id,
 logical_request_id,attempt_id,terminal_result_id,canonical_result_size,canonical_result_blake3,
 byte_result_handle,payload_size,payload_blake3,owner_service_instance_id,owner_generation,
 owner_authority_revision,authenticated_principal_id,authenticated_scope,canonical_descriptor_fingerprint,
 caller_fence,admitted_generation,open_fingerprint,next_chunk_index,lease_revision,opened_at_unix_ms,
 state,terminal_reason,terminal_at_unix_ms,terminal_fingerprint,canonical_lease_bytes,lease_blake3
) VALUES ('object-store-dispatch-authority-schema-v1','$LEASE','boundary-1','cell-1','tenant-1',
 '$LOGICAL','$ATTEMPT','result-$ID',33,$DIGEST,'result/body-$ID',33,$DIGEST,
 'instance-$ID',1,1,'principal','scope',$DIGEST,1,1,$DIGEST,0,1,1500,2,1,1600,$DIGEST,$RECORD,$DIGEST);
