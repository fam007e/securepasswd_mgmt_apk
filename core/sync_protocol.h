#ifndef SYNC_PROTOCOL_H
#define SYNC_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SecurePasswd 2-way sync protocol (v2).
 *
 * Security properties:
 *  - 512-bit (64-byte) pairing secret (PSK) distributed out-of-band via QR code.
 *  - Ephemeral X25519 key exchange authenticated by the PSK (HKDF-SHA256 salt),
 *    giving forward secrecy and mutual authentication.
 *  - ChaCha20-Poly1305 AEAD frames with per-direction keys, monotonically
 *    increasing sequence-number nonces and type/sequence bound AAD
 *    (replay and re-ordering protection).
 *  - Key-confirmation frames carrying the handshake transcript hash.
 *
 * This module is platform-independent (OpenSSL EVP only) and is shared with the
 * Android client. Do not add platform includes here.
 */

#define SPSYNC_VERSION        2
#define SPSYNC_HKDF_INFO      "SecurePasswd-Sync-v2"

/* 512-bit pairing secret distributed via the vsync2: QR payload. */
#define SYNC_PSK_LEN          64
/* X25519 raw public / private keys. */
#define SYNC_EPHEMERAL_LEN    32
/* Per-direction ChaCha20-Poly1305 key and base IV. */
#define SYNC_KEY_LEN          32
#define SYNC_IV_LEN           12
#define SYNC_TAG_LEN          16
/* HKDF output: c2s_key(32) + s2c_key(32) + c2s_iv(12) + s2c_iv(12). */
#define SYNC_SESSION_MATERIAL_LEN (SYNC_KEY_LEN * 2 + SYNC_IV_LEN * 2)

/* Hard upper bound for a single frame payload (sanity check against abuse). */
#define SYNC_FRAME_MAX        (64u * 1024u * 1024u)

typedef enum {
    SYNC_ROLE_SERVER = 0, /* desktop: sends on s2c, receives on c2s */
    SYNC_ROLE_CLIENT = 1  /* mobile: sends on c2s, receives on s2c */
} sync_role_t;

typedef enum {
    SYNC_FRAME_CONFIRM  = 0x01, /* key confirmation (transcript hash) */
    SYNC_FRAME_REQUEST  = 0x02, /* client asks for merged snapshot */
    SYNC_FRAME_SNAPSHOT = 0x03, /* sender's vault snapshot */
    SYNC_FRAME_ACK      = 0x04, /* final acknowledgement */
    SYNC_FRAME_ERROR    = 0x05  /* abort with UTF-8 message payload */
} sync_frame_type_t;

/* Neutral, platform-independent vault record shared by both ends. */
typedef struct {
    char *service;
    char *username;
    char *password;
    char *totp_secret;
    char *recovery_codes;
    int64_t updated_at;
} sync_entry_t;

typedef struct {
    char *service;
    char *username;
    int64_t deleted_at;
} sync_tombstone_t;

typedef struct {
    uint8_t c2s_key[SYNC_KEY_LEN];
    uint8_t s2c_key[SYNC_KEY_LEN];
    uint8_t c2s_iv[SYNC_IV_LEN];
    uint8_t s2c_iv[SYNC_IV_LEN];
    sync_role_t role;
    uint64_t send_seq;
    uint64_t recv_seq;
    uint8_t transcript_hash[32];
} sync_session_t;

/* ------------------------- memory helpers ------------------------- */

void sync_entry_init(sync_entry_t *e);
void sync_entry_wipe(sync_entry_t *e);
void sync_tombstone_wipe(sync_tombstone_t *t);

/* Wipe elements only; safe for arrays that are not heap-allocated by this
 * module (stack arrays, std::vector data, etc.). */
void sync_entries_wipe(sync_entry_t *entries, int count);
void sync_tombstones_wipe(sync_tombstone_t *tombstones, int count);

/* Wipe elements AND free the heap-allocated array (results of
 * sync_snapshot_deserialize). */
void sync_entries_free(sync_entry_t *entries, int count);
void sync_tombstones_free(sync_tombstone_t *tombstones, int count);

/* --------------------------- handshake --------------------------- */

/**
 * Generates an ephemeral X25519 key pair (CSPRNG).
 * @return 0 on success, -1 on error.
 */
int sync_ephemeral_keygen(uint8_t out_pub[SYNC_EPHEMERAL_LEN],
                          uint8_t out_priv[SYNC_EPHEMERAL_LEN]);

/**
 * Derives per-direction session keys from the ephemeral X25519 shared secret
 * and the 64-byte PSK (HKDF-SHA256, PSK as salt). Both parties must call this
 * with identical client_pub/server_pub and their own private key.
 *
 * @return 0 on success, -1 on error.
 */
int sync_session_derive(sync_role_t role,
                        const uint8_t psk[SYNC_PSK_LEN],
                        const uint8_t client_pub[SYNC_EPHEMERAL_LEN],
                        const uint8_t server_pub[SYNC_EPHEMERAL_LEN],
                        const uint8_t own_priv[SYNC_EPHEMERAL_LEN],
                        sync_session_t *out_session);

/** Zeroes all key material in the session. */
void sync_session_zero(sync_session_t *session);

/**
 * Computes the handshake transcript hash (SHA-256 over
 * SPSYNC_HKDF_INFO || client_pub || server_pub) that both sides exchange
 * inside SYNC_FRAME_CONFIRM payloads to authenticate the session.
 */
void sync_transcript_hash(const uint8_t client_pub[SYNC_EPHEMERAL_LEN],
                          const uint8_t server_pub[SYNC_EPHEMERAL_LEN],
                          uint8_t out_hash[32]);

/* ----------------------------- frames ----------------------------- */

/**
 * Encrypts one frame. Wire format: [type u8][len u32 BE][ciphertext||tag].
 * AAD binds frame type and sequence number; the nonce is the per-direction
 * base IV XOR the sequence number. The session's send_seq is incremented.
 *
 * @param out_cap capacity of out; must be >= payload_len + 1 + 4 + SYNC_TAG_LEN.
 * @return 0 on success, -1 on error.
 */
int sync_frame_encrypt(sync_session_t *session, uint8_t type,
                       const uint8_t *payload, size_t payload_len,
                       uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * Decrypts one frame produced by sync_frame_encrypt. Verifies the AEAD tag,
 * the expected frame type and that the sequence number is exactly the next
 * expected one (strict ordering => replay protection). The session's recv_seq
 * is incremented on success.
 *
 * @param out_cap capacity of out; must be >= payload length of the frame.
 * @return 0 on success, -1 on any authentication/format/order failure.
 */
int sync_frame_decrypt(sync_session_t *session, uint8_t expected_type,
                       const uint8_t *frame, size_t frame_len,
                       uint8_t *out, size_t out_cap, size_t *out_len);

/* --------------------------- snapshots --------------------------- */

/**
 * Serializes entries + tombstones into the platform-independent snapshot
 * format (binary, little-endian, length-prefixed strings).
 *
 * @param out newly allocated buffer, caller frees with free() after zeroing.
 * @return 0 on success, -1 on error.
 */
int sync_snapshot_serialize(const sync_entry_t *entries, int entry_count,
                            const sync_tombstone_t *tombstones, int tombstone_count,
                            uint8_t **out, size_t *out_len);

/**
 * Parses a snapshot produced by sync_snapshot_serialize. Strict bounds
 * checking; no length field is trusted without validation.
 * @return 0 on success, -1 on error.
 */
int sync_snapshot_deserialize(const uint8_t *data, size_t len,
                              sync_entry_t **entries, int *entry_count,
                              sync_tombstone_t **tombstones, int *tombstone_count);

/* ----------------------------- merge ------------------------------ */

typedef enum {
    SYNC_MERGE_APPLY_REMOTE  = 0, /* remote entry is new or strictly newer: apply it */
    SYNC_MERGE_KEEP_LOCAL    = 1, /* local is strictly newer: keep, push local to peer */
    SYNC_MERGE_IDENTICAL     = 2, /* both sides already agree */
    SYNC_MERGE_IGNORED       = 3, /* remote entry, but locally tombstoned at/after it */
    SYNC_MERGE_DELETED       = 4  /* local entry deleted on peer: apply deletion */
} sync_merge_action_t;

typedef struct {
    sync_merge_action_t action;
    int is_conflict;      /* both sides changed the same identity differently */
    char *service;
    char *username;
    sync_entry_t winner;  /* populated for APPLY_REMOTE / KEEP_LOCAL / conflicts */
    int64_t tombstone_at; /* populated for DELETED / IGNORED */
} sync_merge_result_t;

typedef struct {
    sync_merge_result_t *results;
    int result_count;
    int added;      /* APPLY_REMOTE where the identity is new locally */
    int updated;    /* APPLY_REMOTE where the identity existed locally */
    int identical;  /* IDENTICAL */
    int deleted;    /* DELETED */
    int conflicts;  /* results flagged is_conflict */
} sync_merge_report_t;

/**
 * Deterministic, symmetric merge of two vault snapshots.
 *
 * Identity is (lowercase(service), lowercase(username)). Rules:
 *  - only on one side -> apply it (unless the other side tombstoned it at or
 *    after its updated_at, in which case the deletion wins / entry ignored);
 *  - identical content -> skip;
 *  - different content -> the entry with the higher updated_at wins; on a tie
 *    the lexicographically larger serialized record wins (side-independent, so
 *    both peers converge to the same result). The loser is flagged as a
 *    conflict for review UIs, but the winner is always recorded so applying
 *    the report keeps both devices consistent.
 *
 * @return 0 on success, -1 on error.
 */
int sync_merge_vaults(const sync_entry_t *local_entries, int local_count,
                      const sync_entry_t *remote_entries, int remote_count,
                      const sync_tombstone_t *local_tombstones, int local_tomb_count,
                      const sync_tombstone_t *remote_tombstones, int remote_tomb_count,
                      sync_merge_report_t *report);

void sync_merge_report_free(sync_merge_report_t *report);

#ifdef __cplusplus
}
#endif

#endif // SYNC_PROTOCOL_H
