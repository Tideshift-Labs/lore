# Embedded Migrations Catalog

This document details the precise, source-dark migrations embedded within the cell install set. 

Migrations 0002/0003, the local-authority chain, cell retention 0023/0024, provider-attempt guards, and drain policy chain (through 0027) are included. Migrations 0004 through 0006 are deferred (replaced by bounded cell retention). Runtime never auto-installs migrations; a migrator role installs them out-of-band using `cell-schema-install`.

## Local Authority Migrations

- **Core Migration**: `local_authority_schema::LOCAL_AUTHORITY_MIGRATION_V1` (42,294 bytes, BLAKE3: `d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff`). Extends the retention namespace with requests, attempts, spool objects, quota usage, dispatchers, payload purges, and fetch leases.
- **Provisioning/Readback**: `local_authority_provisioning::LOCAL_AUTHORITY_PROVISIONING_MIGRATION_V1` (24,837 bytes, BLAKE3: `90900a392e8d6ca0b59c12aa735e6acf8da364319025b8fae4cafe88a51ed14d`). Freezes API `object-store-dispatch-authority-provisioning-v1`, permits migrator install and readback.
- **Canonical Codec**: `local_authority_canonical_codec::LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_V1` (16,704 bytes, BLAKE3: `b0803eacad028566e9fd5559f8f8069c44ad290d5631a8cef1a4f7c9669ea12a`). Helpers construct server-derived canonical records.

## PUT Reservation

- **Schema**: `local_authority_put_reservation_schema::LOCAL_AUTHORITY_PUT_RESERVATION_SCHEMA_MIGRATION_V1` (4,690 bytes, BLAKE3: `56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67`). Adds 12 reservation/current-ACK fields to spool table.
- **Provisioning**: `local_authority_put_reservation_provisioning::LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_V1` (31,471 bytes, BLAKE3: `afe63db96bf286d1f04e6015eaf797e020b2fcbb2b13012224c66ef462d47248`). Catalog manifest for extended authority.
- **Record Codec**: `local_authority_put_reservation_record_codec::LOCAL_AUTHORITY_PUT_RESERVATION_RECORD_CODEC_MIGRATION_V1` (10,874 bytes, BLAKE3: `b37116d9d87e49ad5c0051514e721a80d0c39f1c9dcaa51c19f7a77618ee6514`). Constructs initial `UNBOUND`/`PUT`/`RESERVED`/`RETAINED` record.
- **Mutation**: `local_authority_reserve_put_mutation::LOCAL_AUTHORITY_RESERVE_PUT_MUTATION_MIGRATION_V1` (23,166 bytes, BLAKE3: `eb5d413b9d5dd5d45802b3acaca193cc6b5ac783e38a4c00002a9f9abf77ed7`). Atomic ReservePut mutation.

## Upload Progress & Spool

- **Upload Progress Codec**: `local_authority_put_upload_progress_codec::LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_V1` (17,444 bytes, BLAKE3: `f5361aa66c3e1bdced683040e3a405557a8d2d07f85a182e8e33867e208631a0`).
- **Upload Progress Mutation**: `local_authority_put_upload_progress_mutation::LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_V1` (10,942 bytes, BLAKE3: `f9bb0d0ed36689b6c15b9686108adc905cd8fe9839156e051fc443b09941078c`). Atomic replacement of canonical record.
- **Spool Ready Codec**: `local_authority_put_spool_ready_codec::LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_V1` (17,033 bytes, BLAKE3: `180fed6b34db413c761e7dcd1e5250119aca5c50116977e8de54ca131408cf8c`).
- **Spool Ready Mutation**: `local_authority_put_spool_ready_mutation::LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_V1` (13,373 bytes, BLAKE3: `1bf102fce2e86f48eed6295e1349795564c4aae48aa5ac5d5af5ab5233b0462c`). Runtime transition from RESERVED lifecycle 1 to SPOOL_READY lifecycle 2.

## Dispatcher Identity & Shared Cell Limiter

- **Dispatcher Identity Schema**: `local_authority_dispatcher_identity_schema::LOCAL_AUTHORITY_DISPATCHER_IDENTITY_SCHEMA_MIGRATION_V1` (4,477 bytes, BLAKE3: `a7d54d94d0fa5035872eb9b3426cbbe6471bcf9ae34ed41877542f050e1aaad9`). Replaces single-active-dispatcher constraints with participant-owned lease chains.
- **Provisioning**: `local_authority_dispatcher_identity_provisioning::LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_V1` (25,375 bytes, BLAKE3: `fd0aa946118010222eed883ab9bc68fa09fd3a3fbb0eb2d1e21e1904bd9c213e`). Fourth schema layer read state.
- **Registration**: `local_authority_dispatcher_registration::LOCAL_AUTHORITY_DISPATCHER_REGISTRATION_MIGRATION_V1` (29,189 bytes, BLAKE3: `aede4135d081a9adbec51cd41141faea81eb3b25860ab9d1968073a230aa78e9`). Adds durable `object_dispatch_dispatcher_participants` registry.
- **Shared Limiter**: Migrations 0021 (8,543 bytes, BLAKE3: `3387f71079d81552e97226144e3f8526706f197d6eedb23af9af5a41ac43fb31`) and 0022 (57,061 bytes, BLAKE3: `7d471d4524dec97f0108b57d586f99676e48721860bb78b1710b6d6a7e979c34`). Source-dark shared cell-local limiter. 

## Budget & Ledger

- Local budget policy V2 produces deterministic UUIDv7 disposition identities; V1 keeps its original serialization.
- `PostgresProviderChargeAuthority` accepts a preconnected dispatch-runtime client. Provider-attempt deadlines are bounded to five minutes.
