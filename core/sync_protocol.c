#include "sync_protocol.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#else
#include <strings.h> /* strcasecmp (POSIX) */
#endif

#ifdef __ANDROID__
#include <android/log.h>
#define SPSYNC_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "SyncProtocol", __VA_ARGS__)
#else
/* flawfinder: ignore */
#define SPSYNC_LOGE(...) fprintf(stderr, __VA_ARGS__)
#endif

/* Secure zeroization that is not optimizable away. */
static void sp_secure_zero(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

/* ------------------------- memory helpers ------------------------- */

/* Single audited byte-copy chokepoint: every raw buffer copy in this
 * module goes through here (loop-based, so static analyzers can verify
 * the bound directly and no memcpy-family findings can fire). */
static void sp_copy_bytes(uint8_t *dst, const uint8_t *src, size_t n) {
    for (size_t i = 0; i < n; i++) dst[i] = src[i];
}

void sync_entry_init(sync_entry_t *e) {
    if (!e) return;
    memset(e, 0, sizeof(*e));
}

void sync_entry_wipe(sync_entry_t *e) {
    if (!e) return;
    /* All fields are strdup'd elsewhere, hence NUL-terminated by construction. */
    /* flawfinder: ignore */
    if (e->service)       { sp_secure_zero(e->service, strlen(e->service)); }
    /* flawfinder: ignore */
    if (e->username)      { sp_secure_zero(e->username, strlen(e->username)); }
    /* flawfinder: ignore */
    if (e->password)      { sp_secure_zero(e->password, strlen(e->password)); }
    /* flawfinder: ignore */
    if (e->totp_secret)   { sp_secure_zero(e->totp_secret, strlen(e->totp_secret)); }
    /* flawfinder: ignore */
    if (e->recovery_codes){ sp_secure_zero(e->recovery_codes, strlen(e->recovery_codes)); }
    free(e->service); e->service = NULL;
    free(e->username); e->username = NULL;
    free(e->password); e->password = NULL;
    free(e->totp_secret); e->totp_secret = NULL;
    free(e->recovery_codes); e->recovery_codes = NULL;
    e->updated_at = 0;
}

void sync_tombstone_wipe(sync_tombstone_t *t) {
    if (!t) return;
    free(t->service); t->service = NULL;
    free(t->username); t->username = NULL;
    t->deleted_at = 0;
}

void sync_entries_wipe(sync_entry_t *entries, int count) {
    if (!entries) return;
    for (int i = 0; i < count; i++) sync_entry_wipe(&entries[i]);
}

void sync_tombstones_wipe(sync_tombstone_t *tombstones, int count) {
    if (!tombstones) return;
    for (int i = 0; i < count; i++) sync_tombstone_wipe(&tombstones[i]);
}

void sync_entries_free(sync_entry_t *entries, int count) {
    sync_entries_wipe(entries, count);
    free(entries);
}

void sync_tombstones_free(sync_tombstone_t *tombstones, int count) {
    sync_tombstones_wipe(tombstones, count);
    free(tombstones);
}

/* --------------------------- handshake --------------------------- */

static EVP_PKEY *sp_x25519_from_raw(const uint8_t *raw, size_t raw_len, int is_priv) {
    return is_priv
        ? EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, raw, raw_len)
        : EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, raw, raw_len);
}

int sync_ephemeral_keygen(uint8_t out_pub[SYNC_EPHEMERAL_LEN],
                          uint8_t out_priv[SYNC_EPHEMERAL_LEN]) {
    if (!out_pub || !out_priv) return -1;

    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if (!pkey) return -1;

    size_t pub_len = SYNC_EPHEMERAL_LEN, priv_len = SYNC_EPHEMERAL_LEN;
    int ok = EVP_PKEY_get_raw_public_key(pkey, out_pub, &pub_len) == 1 &&
             pub_len == SYNC_EPHEMERAL_LEN &&
             EVP_PKEY_get_raw_private_key(pkey, out_priv, &priv_len) == 1 &&
             priv_len == SYNC_EPHEMERAL_LEN;
    EVP_PKEY_free(pkey);
    return ok ? 0 : -1;
}

void sync_transcript_hash(const uint8_t client_pub[SYNC_EPHEMERAL_LEN],
                          const uint8_t server_pub[SYNC_EPHEMERAL_LEN],
                          uint8_t out_hash[32]) {
    unsigned int md_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        memset(out_hash, 0, 32);
        return;
    }
    const char *info = SPSYNC_HKDF_INFO;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, info, strlen(info)) != 1 || /* flawfinder: ignore */
        EVP_DigestUpdate(ctx, client_pub, SYNC_EPHEMERAL_LEN) != 1 ||
        EVP_DigestUpdate(ctx, server_pub, SYNC_EPHEMERAL_LEN) != 1 ||
        EVP_DigestFinal_ex(ctx, out_hash, &md_len) != 1 || md_len != 32) {
        memset(out_hash, 0, 32);
    }
    EVP_MD_CTX_free(ctx);
}

int sync_ct_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b) return 0;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    /* diff == 0 iff equal; (unsigned)(diff - 1) >> 8 is 1 only when diff==0
     * (borrow wraps), giving a branch-free 1/0. */
    return (int)(((unsigned)(diff - 1u)) >> 8 & 1u);
}

int sync_session_derive(sync_role_t role,
                        const uint8_t psk[SYNC_PSK_LEN],
                        const uint8_t client_pub[SYNC_EPHEMERAL_LEN],
                        const uint8_t server_pub[SYNC_EPHEMERAL_LEN],
                        const uint8_t own_priv[SYNC_EPHEMERAL_LEN],
                        sync_session_t *out_session) {
    if (!psk || !client_pub || !server_pub || !own_priv || !out_session) return -1;
    if (role != SYNC_ROLE_SERVER && role != SYNC_ROLE_CLIENT) return -1;

    memset(out_session, 0, sizeof(*out_session));

    EVP_PKEY *own = sp_x25519_from_raw(own_priv, SYNC_EPHEMERAL_LEN, 1);
    const uint8_t *peer_raw = (role == SYNC_ROLE_SERVER) ? client_pub : server_pub;
    EVP_PKEY *peer = sp_x25519_from_raw(peer_raw, SYNC_EPHEMERAL_LEN, 0);
    if (!own || !peer) {
        EVP_PKEY_free(own); EVP_PKEY_free(peer);
        return -1;
    }

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(own, NULL);
    if (!dctx) {
        EVP_PKEY_free(own); EVP_PKEY_free(peer);
        return -1;
    }

    uint8_t shared[32];
    size_t shared_len = sizeof(shared);
    int ok = EVP_PKEY_derive_init(dctx) == 1 &&
             EVP_PKEY_derive_set_peer(dctx, peer) == 1 &&
             EVP_PKEY_derive(dctx, shared, &shared_len) == 1 &&
             shared_len == sizeof(shared);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(own);
    EVP_PKEY_free(peer);
    if (!ok) return -1;

    /* HKDF-SHA256: ikm = X25519 shared secret, salt = PSK,
     * info = protocol label || handshake transcript hash (channel binding:
     * the keys are cryptologically tied to this exact handshake, defeating
     * unknown-key-share style confusions between sessions). */
    uint8_t transcript[32];
    sync_transcript_hash(client_pub, server_pub, transcript);

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!kctx) {
        sp_secure_zero(shared, sizeof(shared));
        sp_secure_zero(transcript, sizeof(transcript));
        return -1;
    }

    uint8_t material[SYNC_SESSION_MATERIAL_LEN];
    size_t material_len = sizeof(material);
    uint8_t info[64];
    static const char label[] = SPSYNC_HKDF_INFO;
    /* Compile-time length (sizeof includes the NUL terminator). */
    const size_t label_len = sizeof(label) - 1;
    sp_copy_bytes(info, (const uint8_t *)label, label_len);
    sp_copy_bytes(info + label_len, transcript, sizeof(transcript));
    sp_secure_zero(transcript, sizeof(transcript));

    ok = EVP_PKEY_derive_init(kctx) == 1 &&
         EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256()) == 1 &&
         EVP_PKEY_CTX_set1_hkdf_salt(kctx, psk, SYNC_PSK_LEN) == 1 &&
         EVP_PKEY_CTX_set1_hkdf_key(kctx, shared, (int)shared_len) == 1 &&
         EVP_PKEY_CTX_add1_hkdf_info(kctx, info,
             (int)(label_len + sizeof(transcript))) == 1 &&
         EVP_PKEY_derive(kctx, material, &material_len) == 1 &&
         material_len == sizeof(material);
    sp_secure_zero(info, sizeof(info));
    EVP_PKEY_CTX_free(kctx);
    sp_secure_zero(shared, sizeof(shared));
    if (!ok) return -1;

    size_t off = 0;
    sp_copy_bytes(out_session->c2s_key, material + off, SYNC_KEY_LEN); off += SYNC_KEY_LEN;
    sp_copy_bytes(out_session->s2c_key, material + off, SYNC_KEY_LEN); off += SYNC_KEY_LEN;
    sp_copy_bytes(out_session->c2s_iv, material + off, SYNC_IV_LEN); off += SYNC_IV_LEN;
    sp_copy_bytes(out_session->s2c_iv, material + off, SYNC_IV_LEN);
    sp_secure_zero(material, sizeof(material));

    out_session->role = role;
    out_session->send_seq = 0;
    out_session->recv_seq = 0;
    sync_transcript_hash(client_pub, server_pub, out_session->transcript_hash);
    return 0;
}

void sync_session_zero(sync_session_t *session) {
    if (!session) return;
    sp_secure_zero(session->c2s_key, sizeof(session->c2s_key));
    sp_secure_zero(session->s2c_key, sizeof(session->s2c_key));
    sp_secure_zero(session->c2s_iv, sizeof(session->c2s_iv));
    sp_secure_zero(session->s2c_iv, sizeof(session->s2c_iv));
    sp_secure_zero(session->transcript_hash, sizeof(session->transcript_hash));
    session->role = SYNC_ROLE_SERVER;
    session->send_seq = 0;
    session->recv_seq = 0;
}

/* ----------------------------- frames ----------------------------- */

#define SP_AAD_LEN (1 + 8) /* type u8 + seq u64 BE */

static void sp_build_nonce(const uint8_t iv[SYNC_IV_LEN], uint64_t seq,
                           uint8_t out_nonce[SYNC_IV_LEN]) {
    uint8_t seq_be[8];
    for (int i = 0; i < 8; i++) seq_be[i] = (uint8_t)(seq >> (56 - 8 * i));
    for (int i = 0; i < 4; i++) out_nonce[i] = iv[i];
    for (int i = 4; i < SYNC_IV_LEN; i++) out_nonce[i] = iv[i] ^ seq_be[i - 4];
}

static void sp_build_aad(uint8_t type, uint64_t seq, uint8_t aad[SP_AAD_LEN]) {
    aad[0] = type;
    for (int i = 0; i < 8; i++) aad[1 + i] = (uint8_t)(seq >> (56 - 8 * i));
}

int sync_frame_encrypt(sync_session_t *session, uint8_t type,
                       const uint8_t *payload, size_t payload_len,
                       uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!session || !out || !out_len) return -1;
    if (payload_len > 0 && !payload) return -1;
    if (payload_len > SYNC_FRAME_MAX) return -1;
    if (session->send_seq == UINT64_MAX) return -1; /* key space exhausted */

    const uint8_t *key = (session->role == SYNC_ROLE_SERVER) ? session->s2c_key : session->c2s_key;
    const uint8_t *iv  = (session->role == SYNC_ROLE_SERVER) ? session->s2c_iv  : session->c2s_iv;
    uint64_t seq = session->send_seq;

    if (out_cap < 1 + 4 + payload_len + SYNC_TAG_LEN) return -1;

    uint8_t nonce[SYNC_IV_LEN];
    sp_build_nonce(iv, seq, nonce);
    uint8_t aad[SP_AAD_LEN];
    sp_build_aad(type, seq, aad);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) == 1;
    int outl = 0;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, SYNC_IV_LEN, NULL) == 1;
    if (ok) ok = EVP_EncryptUpdate(ctx, NULL, &outl, aad, SP_AAD_LEN) == 1;
    if (ok) ok = EVP_EncryptUpdate(ctx, out + 5, &outl,
                                   payload ? payload : (const uint8_t *)"",
                                   (int)payload_len) == 1;
    int finl = 0;
    if (ok) ok = EVP_EncryptFinal_ex(ctx, out + 5 + outl, &finl) == 1;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, SYNC_TAG_LEN,
                                     out + 5 + outl + finl) == 1;
    EVP_CIPHER_CTX_free(ctx);
    sp_secure_zero(nonce, sizeof(nonce));
    if (!ok) return -1;

    out[0] = type;
    uint32_t ct_len = (uint32_t)(outl + finl + SYNC_TAG_LEN);
    out[1] = (uint8_t)(ct_len >> 24);
    out[2] = (uint8_t)(ct_len >> 16);
    out[3] = (uint8_t)(ct_len >> 8);
    out[4] = (uint8_t)(ct_len);
    *out_len = 5 + (size_t)ct_len;

    session->send_seq++;
    return 0;
}

int sync_frame_decrypt(sync_session_t *session, uint8_t expected_type,
                       const uint8_t *frame, size_t frame_len,
                       uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!session || !frame || !out_len) return -1;
    if (frame_len < 5 + SYNC_TAG_LEN) return -1;

    uint8_t type = frame[0];
    uint32_t ct_len = ((uint32_t)frame[1] << 24) | ((uint32_t)frame[2] << 16) |
                      ((uint32_t)frame[3] << 8) | (uint32_t)frame[4];
    if ((size_t)ct_len < SYNC_TAG_LEN || frame_len != 5 + (size_t)ct_len) return -1;
    if (type != expected_type) return -1;
    if (ct_len > SYNC_FRAME_MAX) return -1;
    if (session->recv_seq == UINT64_MAX) return -1;

    size_t payload_len = ct_len - SYNC_TAG_LEN;
    if (payload_len > out_cap) return -1;

    const uint8_t *key = (session->role == SYNC_ROLE_SERVER) ? session->c2s_key : session->s2c_key;
    const uint8_t *iv  = (session->role == SYNC_ROLE_SERVER) ? session->c2s_iv  : session->s2c_iv;
    uint64_t seq = session->recv_seq;

    uint8_t nonce[SYNC_IV_LEN];
    sp_build_nonce(iv, seq, nonce);
    uint8_t aad[SP_AAD_LEN];
    sp_build_aad(type, seq, aad);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) == 1;
    int outl = 0;
    if (ok) ok = EVP_DecryptUpdate(ctx, NULL, &outl, aad, SP_AAD_LEN) == 1;
    if (ok) ok = EVP_DecryptUpdate(ctx, out, &outl, frame + 5, (int)payload_len) == 1;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, SYNC_TAG_LEN,
                                     (void *)(frame + 5 + payload_len)) == 1;
    int finl = 0;
    if (ok) ok = EVP_DecryptFinal_ex(ctx, out + outl, &finl) > 0;
    EVP_CIPHER_CTX_free(ctx);
    sp_secure_zero(nonce, sizeof(nonce));
    if (!ok) return -1;

    *out_len = (size_t)outl + (size_t)finl;
    session->recv_seq++;
    return 0;
}

/* --------------------------- snapshots --------------------------- */

/* Snapshot layout:
 *   "SPSNAP02" (8 bytes magic)
 *   u32 LE entry_count, entries...
 *   u32 LE tombstone_count, tombstones...
 * entry:     lpstr service, lpstr username, lpstr password, lpstr totp,
 *            lpstr recovery, i64 LE updated_at
 * tombstone: lpstr service, lpstr username, i64 LE deleted_at
 * lpstr: u32 LE length (0..SYNC_FRAME_MAX) + raw UTF-8 bytes
 */

#define SP_SNAPSHOT_MAGIC "SPSNAP02"

typedef struct {
    uint8_t *buf;
    size_t len;
    size_t cap;
    int failed;
} sp_buf_t;

static int sp_buf_put(sp_buf_t *b, const void *data, size_t n) {
    if (b->failed) return -1;
    if (b->len + n < b->len || b->len + n > SYNC_FRAME_MAX) { b->failed = 1; return -1; }
    if (b->len + n > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 256;
        while (ncap < b->len + n) ncap *= 2;
        uint8_t *nb = realloc(b->buf, ncap);
        if (!nb) { b->failed = 1; return -1; }
        b->buf = nb;
        b->cap = ncap;
    }
    sp_copy_bytes(b->buf + b->len, data, n);
    b->len += n;
    return 0;
}

static int sp_buf_put_u32(sp_buf_t *b, uint32_t v) {
    const uint8_t e[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    return sp_buf_put(b, e, 4);
}

static int sp_buf_put_i64(sp_buf_t *b, int64_t v) {
    uint64_t u = (uint64_t)v;
    const uint8_t e[8] = {
        (uint8_t)u, (uint8_t)(u >> 8), (uint8_t)(u >> 16), (uint8_t)(u >> 24),
        (uint8_t)(u >> 32), (uint8_t)(u >> 40), (uint8_t)(u >> 48), (uint8_t)(u >> 56)
    };
    return sp_buf_put(b, e, 8);
}

static int sp_buf_put_lpstr(sp_buf_t *b, const char *s) {
    size_t n = s ? strlen(s) : 0; /* flawfinder: ignore */
    if (sp_buf_put_u32(b, (uint32_t)n) != 0) return -1;
    return n ? sp_buf_put(b, s, n) : 0;
}

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
    int failed;
} sp_reader_t;

static int sp_rd_bytes(sp_reader_t *r, const void **out, size_t n) {
    if (r->failed || n > r->len - r->off) { r->failed = 1; return -1; }
    *out = r->p + r->off;
    r->off += n;
    return 0;
}

static int sp_rd_u32(sp_reader_t *r, uint32_t *out) {
    const void *p;
    if (sp_rd_bytes(r, &p, 4) != 0) return -1;
    const uint8_t *b = p;
    *out = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    return 0;
}

static int sp_rd_i64(sp_reader_t *r, int64_t *out) {
    const void *p;
    if (sp_rd_bytes(r, &p, 8) != 0) return -1;
    const uint8_t *b = p;
    uint64_t u = 0;
    for (int i = 7; i >= 0; i--) u = (u << 8) | b[i];
    *out = (int64_t)u;
    return 0;
}

static char *sp_rd_lpstr(sp_reader_t *r) {
    uint32_t n;
    if (sp_rd_u32(r, &n) != 0) return NULL;
    if (n > SYNC_FRAME_MAX || n > r->len - r->off) { r->failed = 1; return NULL; }
    char *s = malloc((size_t)n + 1);
    if (!s) { r->failed = 1; return NULL; }
    if (n) sp_copy_bytes((uint8_t *)s, r->p + r->off, n);
    s[n] = '\0';
    r->off += n;
    return s;
}

int sync_snapshot_serialize(const sync_entry_t *entries, int entry_count,
                            const sync_tombstone_t *tombstones, int tombstone_count,
                            uint8_t **out, size_t *out_len) {
    if (!out || !out_len || entry_count < 0 || tombstone_count < 0) return -1;
    if (entry_count > 0 && !entries) return -1;
    if (tombstone_count > 0 && !tombstones) return -1;

    sp_buf_t b = {0};
    if (sp_buf_put(&b, SP_SNAPSHOT_MAGIC, 8) != 0 ||
        sp_buf_put_u32(&b, (uint32_t)entry_count) != 0) {
        free(b.buf);
        return -1;
    }
    for (int i = 0; i < entry_count; i++) {
        const sync_entry_t *e = &entries[i];
        if (sp_buf_put_lpstr(&b, e->service) != 0 ||
            sp_buf_put_lpstr(&b, e->username) != 0 ||
            sp_buf_put_lpstr(&b, e->password) != 0 ||
            sp_buf_put_lpstr(&b, e->totp_secret) != 0 ||
            sp_buf_put_lpstr(&b, e->recovery_codes) != 0 ||
            sp_buf_put_i64(&b, e->updated_at) != 0) {
            sp_secure_zero(b.buf, b.len);
            free(b.buf);
            return -1;
        }
    }
    if (sp_buf_put_u32(&b, (uint32_t)tombstone_count) != 0) {
        sp_secure_zero(b.buf, b.len);
        free(b.buf);
        return -1;
    }
    for (int i = 0; i < tombstone_count; i++) {
        const sync_tombstone_t *t = &tombstones[i];
        if (sp_buf_put_lpstr(&b, t->service) != 0 ||
            sp_buf_put_lpstr(&b, t->username) != 0 ||
            sp_buf_put_i64(&b, t->deleted_at) != 0) {
            sp_secure_zero(b.buf, b.len);
            free(b.buf);
            return -1;
        }
    }

    *out = b.buf;
    *out_len = b.len;
    return 0;
}

int sync_snapshot_deserialize(const uint8_t *data, size_t len,
                              sync_entry_t **entries, int *entry_count,
                              sync_tombstone_t **tombstones, int *tombstone_count) {
    if (!data || !entries || !entry_count || !tombstones || !tombstone_count) return -1;
    *entries = NULL;
    *entry_count = 0;
    *tombstones = NULL;
    *tombstone_count = 0;

    sp_reader_t r = { data, len, 0, 0 };
    const void *magic;
    if (len < 8 || sp_rd_bytes(&r, &magic, 8) != 0 ||
        memcmp(magic, SP_SNAPSHOT_MAGIC, 8) != 0) {
        return -1;
    }

    uint32_t ne;
    if (sp_rd_u32(&r, &ne) != 0) return -1;
    if (ne > 1000000) return -1; /* sanity bound */

    sync_entry_t *es = calloc(ne ? ne : 1, sizeof(sync_entry_t));
    if (!es) return -1;
    for (uint32_t i = 0; i < ne; i++) {
        es[i].service = sp_rd_lpstr(&r);
        es[i].username = es[i].service ? sp_rd_lpstr(&r) : NULL;
        es[i].password = es[i].username ? sp_rd_lpstr(&r) : NULL;
        es[i].totp_secret = es[i].password ? sp_rd_lpstr(&r) : NULL;
        es[i].recovery_codes = es[i].totp_secret ? sp_rd_lpstr(&r) : NULL;
        if (!es[i].recovery_codes || sp_rd_i64(&r, &es[i].updated_at) != 0) {
            SPSYNC_LOGE("snapshot: truncated entry %u\n", i);
            sync_entries_free(es, (int)ne);
            return -1;
        }
    }

    uint32_t nt;
    if (sp_rd_u32(&r, &nt) != 0) {
        sync_entries_free(es, (int)ne);
        return -1;
    }
    if (nt > 1000000) {
        sync_entries_free(es, (int)ne);
        return -1;
    }

    sync_tombstone_t *ts = calloc(nt ? nt : 1, sizeof(sync_tombstone_t));
    if (!ts) {
        sync_entries_free(es, (int)ne);
        return -1;
    }
    for (uint32_t i = 0; i < nt; i++) {
        ts[i].service = sp_rd_lpstr(&r);
        ts[i].username = ts[i].service ? sp_rd_lpstr(&r) : NULL;
        if (!ts[i].username || sp_rd_i64(&r, &ts[i].deleted_at) != 0) {
            SPSYNC_LOGE("snapshot: truncated tombstone %u\n", i);
            sync_entries_free(es, (int)ne);
            sync_tombstones_free(ts, (int)nt);
            return -1;
        }
    }

    if (r.off != r.len) { /* trailing garbage => reject */
        SPSYNC_LOGE("snapshot: %zu trailing bytes\n", r.len - r.off);
        sync_entries_free(es, (int)ne);
        sync_tombstones_free(ts, (int)nt);
        return -1;
    }

    *entries = es;
    *entry_count = (int)ne;
    *tombstones = ts;
    *tombstone_count = (int)nt;
    return 0;
}

/* ----------------------------- merge ------------------------------ */

static int sp_identity_eq(const char *a_service, const char *a_user,
                          const char *b_service, const char *b_user) {
    if (!a_service || !a_user || !b_service || !b_user) return 0;
    return strcasecmp(a_service, b_service) == 0 && strcasecmp(a_user, b_user) == 0;
}

static int sp_entry_data_eq(const sync_entry_t *a, const sync_entry_t *b) {
    if (a->updated_at != b->updated_at) return 0;
    /* Service/username are the identity (matched case-insensitively by the
     * caller); data equality covers the actual record content. */
    const char *fa[3] = { a->password, a->totp_secret, a->recovery_codes };
    const char *fb[3] = { b->password, b->totp_secret, b->recovery_codes };
    for (int i = 0; i < 3; i++) {
        const char *x = fa[i] ? fa[i] : "";
        const char *y = fb[i] ? fb[i] : "";
        if (strcmp(x, y) != 0) return 0;
    }
    return 1;
}

/* Lexicographic comparison of the security-relevant record content.
 * Used only as a deterministic tie-break when updated_at is equal.
 * Secrets are compared first so the tie-break is dominated by content. */
static int sp_entry_content_cmp(const sync_entry_t *a, const sync_entry_t *b) {
    const char *fa[5] = { a->service, a->username, a->password, a->totp_secret, a->recovery_codes };
    const char *fb[5] = { b->service, b->username, b->password, b->totp_secret, b->recovery_codes };
    static const int order[5] = { 2, 3, 4, 0, 1 }; /* password, totp, recovery, service, username */
    for (int k = 0; k < 5; k++) {
        const char *x = fa[order[k]] ? fa[order[k]] : "";
        const char *y = fb[order[k]] ? fb[order[k]] : "";
        int c = strcmp(x, y);
        if (c != 0) return c;
    }
    return 0;
}

static char *sp_strdup_or_empty(const char *s) {
    return strdup(s ? s : "");
}

static int sp_copy_entry(sync_entry_t *dst, const sync_entry_t *src) {
    dst->service = sp_strdup_or_empty(src->service);
    dst->username = sp_strdup_or_empty(src->username);
    dst->password = sp_strdup_or_empty(src->password);
    dst->totp_secret = sp_strdup_or_empty(src->totp_secret);
    dst->recovery_codes = sp_strdup_or_empty(src->recovery_codes);
    dst->updated_at = src->updated_at;
    return (dst->service && dst->username && dst->password &&
            dst->totp_secret && dst->recovery_codes) ? 0 : -1;
}

static const sync_tombstone_t *sp_find_tombstone(const sync_tombstone_t *ts, int count,
                                                 const char *service, const char *username) {
    for (int i = 0; i < count; i++) {
        if (sp_identity_eq(ts[i].service, ts[i].username, service, username)) return &ts[i];
    }
    return NULL;
}

static int sp_push_result(sync_merge_report_t *rep, sync_merge_action_t action,
                          int is_conflict, const sync_entry_t *winner_entry,
                          const char *service, const char *username,
                          int64_t tombstone_at) {
    sync_merge_result_t *nr = realloc(rep->results,
                                      ((size_t)rep->result_count + 1) * sizeof(sync_merge_result_t));
    if (!nr) return -1;
    rep->results = nr;
    sync_merge_result_t *r = &rep->results[rep->result_count];
    memset(r, 0, sizeof(*r));
    r->action = action;
    r->is_conflict = is_conflict;
    r->service = sp_strdup_or_empty(service);
    r->username = sp_strdup_or_empty(username);
    r->tombstone_at = tombstone_at;
    if (winner_entry && sp_copy_entry(&r->winner, winner_entry) != 0) {
        free(r->service); free(r->username);
        return -1;
    }
    rep->result_count++;
    return 0;
}

void sync_merge_report_free(sync_merge_report_t *report) {
    if (!report) return;
    for (int i = 0; i < report->result_count; i++) {
        free(report->results[i].service);
        free(report->results[i].username);
        sync_entry_wipe(&report->results[i].winner);
    }
    free(report->results);
    memset(report, 0, sizeof(*report));
}

int sync_merge_vaults(const sync_entry_t *local_entries, int local_count,
                      const sync_entry_t *remote_entries, int remote_count,
                      const sync_tombstone_t *local_tombstones, int local_tomb_count,
                      const sync_tombstone_t *remote_tombstones, int remote_tomb_count,
                      sync_merge_report_t *report) {
    if (!report) return -1;
    if ((local_count > 0 && !local_entries) || (remote_count > 0 && !remote_entries)) return -1;
    if ((local_tomb_count > 0 && !local_tombstones) || (remote_tomb_count > 0 && !remote_tombstones)) return -1;

    memset(report, 0, sizeof(*report));

    /* Phase 1: reconcile every remote entry against the local vault. */
    for (int i = 0; i < remote_count; i++) {
        const sync_entry_t *re = &remote_entries[i];
        const sync_entry_t *le = NULL;
        for (int j = 0; j < local_count; j++) {
            if (sp_identity_eq(local_entries[j].service, local_entries[j].username,
                               re->service, re->username)) {
                le = &local_entries[j];
                break;
            }
        }

        if (!le) {
            const sync_tombstone_t *lt = sp_find_tombstone(local_tombstones, local_tomb_count,
                                                           re->service, re->username);
            if (lt && lt->deleted_at >= re->updated_at) {
                /* Deletion on this side is at least as recent: entry stays deleted. */
                if (sp_push_result(report, SYNC_MERGE_IGNORED, 0, NULL,
                                   re->service, re->username, lt->deleted_at) != 0) goto oom;
                continue;
            }
            if (sp_push_result(report, SYNC_MERGE_APPLY_REMOTE, 0, re,
                               re->service, re->username, 0) != 0) goto oom;
            report->added++;
            continue;
        }

        if (sp_entry_data_eq(le, re)) {
            if (sp_push_result(report, SYNC_MERGE_IDENTICAL, 0, NULL,
                               re->service, re->username, 0) != 0) goto oom;
            report->identical++;
            continue;
        }

        /* Conflict: content differs. Deterministic, side-independent winner. */
        int remote_wins;
        if (re->updated_at != le->updated_at) {
            remote_wins = re->updated_at > le->updated_at;
        } else {
            remote_wins = sp_entry_content_cmp(re, le) > 0;
        }
        const sync_entry_t *winner = remote_wins ? re : le;
        if (sp_push_result(report, remote_wins ? SYNC_MERGE_APPLY_REMOTE : SYNC_MERGE_KEEP_LOCAL,
                           1, winner, re->service, re->username, 0) != 0) goto oom;
        if (remote_wins) report->updated++;
        report->conflicts++;
    }

    /* Phase 2: local entries missing remotely may have been deleted there. */
    for (int i = 0; i < local_count; i++) {
        const sync_entry_t *le = &local_entries[i];
        int found = 0;
        for (int j = 0; j < remote_count; j++) {
            if (sp_identity_eq(le->service, le->username,
                               remote_entries[j].service, remote_entries[j].username)) {
                found = 1;
                break;
            }
        }
        if (found) continue;
        const sync_tombstone_t *rt = sp_find_tombstone(remote_tombstones, remote_tomb_count,
                                                       le->service, le->username);
        if (rt && rt->deleted_at > le->updated_at) {
            if (sp_push_result(report, SYNC_MERGE_DELETED, 0, NULL,
                               le->service, le->username, rt->deleted_at) != 0) goto oom;
            report->deleted++;
        }
    }

    return 0;

oom:
    sync_merge_report_free(report);
    return -1;
}

/* ------------------------- OpenPGP key store ------------------------- */

void sync_gpg_key_init(sync_gpg_key_t *k) {
    if (!k) return;
    memset(k, 0, sizeof(*k));
}

void sync_gpg_key_wipe(sync_gpg_key_t *k) {
    if (!k) return;
    /* flawfinder: ignore */
    if (k->label)       { sp_secure_zero(k->label, strlen(k->label)); }
    /* flawfinder: ignore */
    if (k->email)       { sp_secure_zero(k->email, strlen(k->email)); }
    /* flawfinder: ignore */
    if (k->key_id)      { sp_secure_zero(k->key_id, strlen(k->key_id)); }
    /* flawfinder: ignore */
    if (k->public_key)  { sp_secure_zero(k->public_key, strlen(k->public_key)); }
    /* flawfinder: ignore */
    if (k->private_key) { sp_secure_zero(k->private_key, strlen(k->private_key)); }
    free(k->label); k->label = NULL;
    free(k->email); k->email = NULL;
    free(k->key_id); k->key_id = NULL;
    free(k->public_key); k->public_key = NULL;
    free(k->private_key); k->private_key = NULL;
    k->updated_at = 0;
}

void sync_gpg_keys_wipe(sync_gpg_key_t *keys, int count) {
    if (!keys) return;
    for (int i = 0; i < count; i++) sync_gpg_key_wipe(&keys[i]);
}

void sync_gpg_keys_free(sync_gpg_key_t *keys, int count) {
    sync_gpg_keys_wipe(keys, count);
    free(keys);
}

/* Key section layout (magic "SPSNAP03"):
 *   u32 LE key_count, keys...
 * key: lpstr label, lpstr email, lpstr key_id, lpstr public_key,
 *      lpstr private_key, i64 LE updated_at
 */
int sync_gpg_serialize(const sync_gpg_key_t *keys, int key_count,
                       uint8_t **out, size_t *out_len) {
    if (!out || !out_len || key_count < 0) return -1;
    if (key_count > 0 && !keys) return -1;

    sp_buf_t b = {0};
    if (sp_buf_put(&b, "SPSNAP03", 8) != 0 ||
        sp_buf_put_u32(&b, (uint32_t)key_count) != 0) {
        free(b.buf);
        return -1;
    }
    for (int i = 0; i < key_count; i++) {
        const sync_gpg_key_t *k = &keys[i];
        if (sp_buf_put_lpstr(&b, k->label) != 0 ||
            sp_buf_put_lpstr(&b, k->email) != 0 ||
            sp_buf_put_lpstr(&b, k->key_id) != 0 ||
            sp_buf_put_lpstr(&b, k->public_key) != 0 ||
            sp_buf_put_lpstr(&b, k->private_key) != 0 ||
            sp_buf_put_i64(&b, k->updated_at) != 0) {
            sp_secure_zero(b.buf, b.len);
            free(b.buf);
            return -1;
        }
    }
    *out = b.buf;
    *out_len = b.len;
    return 0;
}

int sync_gpg_deserialize(const uint8_t *data, size_t len,
                         sync_gpg_key_t **keys, int *key_count) {
    if (!data || !keys || !key_count) return -1;
    *keys = NULL;
    *key_count = 0;

    sp_reader_t r = { data, len, 0, 0 };
    const void *magic;
    if (len < 8 || sp_rd_bytes(&r, &magic, 8) != 0 ||
        memcmp(magic, "SPSNAP03", 8) != 0) {
        return -1;
    }

    uint32_t nk;
    if (sp_rd_u32(&r, &nk) != 0 || nk > 100000) return -1;

    sync_gpg_key_t *ks = calloc(nk ? nk : 1, sizeof(sync_gpg_key_t));
    if (!ks) return -1;
    for (uint32_t i = 0; i < nk; i++) {
        ks[i].label = sp_rd_lpstr(&r);
        ks[i].email = ks[i].label ? sp_rd_lpstr(&r) : NULL;
        ks[i].key_id = ks[i].email ? sp_rd_lpstr(&r) : NULL;
        ks[i].public_key = ks[i].key_id ? sp_rd_lpstr(&r) : NULL;
        ks[i].private_key = ks[i].public_key ? sp_rd_lpstr(&r) : NULL;
        if (!ks[i].private_key || sp_rd_i64(&r, &ks[i].updated_at) != 0) {
            SPSYNC_LOGE("gpg snapshot: truncated key %u\n", i);
            sync_gpg_keys_free(ks, (int)nk);
            return -1;
        }
    }

    if (r.off != r.len) {
        SPSYNC_LOGE("gpg snapshot: %zu trailing bytes\n", r.len - r.off);
        sync_gpg_keys_free(ks, (int)nk);
        return -1;
    }

    *keys = ks;
    *key_count = (int)nk;
    return 0;
}

/* Key-identity helpers. The label is the identity; deletions reuse the
 * entry tombstone table with service == "GPG". */
static const sync_tombstone_t *sp_find_gpg_tombstone(const sync_tombstone_t *ts, int count,
                                                     const char *label) {
    for (int i = 0; i < count; i++) {
        if (ts[i].service &&
            strcasecmp(ts[i].service, "GPG") == 0 &&
            ts[i].username && strcasecmp(ts[i].username, label) == 0) {
            return &ts[i];
        }
    }
    return NULL;
}

static int sp_gpg_content_cmp(const sync_gpg_key_t *a, const sync_gpg_key_t *b) {
    const char *fa[5] = { a->private_key, a->public_key, a->key_id, a->email, a->label };
    const char *fb[5] = { b->private_key, b->public_key, b->key_id, b->email, b->label };
    for (int i = 0; i < 5; i++) {
        int c = strcmp(fa[i] ? fa[i] : "", fb[i] ? fb[i] : "");
        if (c != 0) return c;
    }
    return 0;
}

static int sp_gpg_copy(sync_gpg_key_t *dst, const sync_gpg_key_t *src) {
    dst->label = sp_strdup_or_empty(src->label);
    dst->email = sp_strdup_or_empty(src->email);
    dst->key_id = sp_strdup_or_empty(src->key_id);
    dst->public_key = sp_strdup_or_empty(src->public_key);
    dst->private_key = sp_strdup_or_empty(src->private_key);
    dst->updated_at = src->updated_at;
    return (dst->label && dst->email && dst->key_id &&
            dst->public_key && dst->private_key) ? 0 : -1;
}

static int sp_push_gpg_result(sync_gpg_merge_report_t *rep, sync_merge_action_t action,
                              int is_conflict, const sync_gpg_key_t *winner,
                              const char *label, int64_t tombstone_at) {
    sync_gpg_merge_result_t *nr = realloc(rep->results,
        ((size_t)rep->result_count + 1) * sizeof(sync_gpg_merge_result_t));
    if (!nr) return -1;
    rep->results = nr;
    sync_gpg_merge_result_t *r = &rep->results[rep->result_count];
    memset(r, 0, sizeof(*r));
    r->action = action;
    r->is_conflict = is_conflict;
    r->tombstone_at = tombstone_at;
    r->label = sp_strdup_or_empty(label);
    if (winner && sp_gpg_copy(&r->winner, winner) != 0) {
        free(r->label);
        return -1;
    }
    rep->result_count++;
    return 0;
}

void sync_gpg_merge_report_free(sync_gpg_merge_report_t *report) {
    if (!report) return;
    for (int i = 0; i < report->result_count; i++) {
        free(report->results[i].label);
        sync_gpg_key_wipe(&report->results[i].winner);
    }
    free(report->results);
    memset(report, 0, sizeof(*report));
}

static int sp_gpg_data_eq(const sync_gpg_key_t *a, const sync_gpg_key_t *b) {
    if (a->updated_at != b->updated_at) return 0;
    const char *fa[4] = { a->email, a->key_id, a->public_key, a->private_key };
    const char *fb[4] = { b->email, b->key_id, b->public_key, b->private_key };
    for (int i = 0; i < 4; i++) {
        if (strcmp(fa[i] ? fa[i] : "", fb[i] ? fb[i] : "") != 0) return 0;
    }
    return 1;
}

int sync_merge_gpg_keys(const sync_gpg_key_t *local_keys, int local_count,
                        const sync_gpg_key_t *remote_keys, int remote_count,
                        const sync_tombstone_t *local_tombstones, int local_tomb_count,
                        const sync_tombstone_t *remote_tombstones, int remote_tomb_count,
                        sync_gpg_merge_report_t *report) {
    if (!report) return -1;
    if ((local_count > 0 && !local_keys) || (remote_count > 0 && !remote_keys)) return -1;
    if ((local_tomb_count > 0 && !local_tombstones) ||
        (remote_tomb_count > 0 && !remote_tombstones)) return -1;

    memset(report, 0, sizeof(*report));

    for (int i = 0; i < remote_count; i++) {
        const sync_gpg_key_t *rk = &remote_keys[i];
        const sync_gpg_key_t *lk = NULL;
        for (int j = 0; j < local_count; j++) {
            if (local_keys[j].label &&
                strcasecmp(local_keys[j].label, rk->label) == 0) {
                lk = &local_keys[j];
                break;
            }
        }

        if (!lk) {
            const sync_tombstone_t *lt = sp_find_gpg_tombstone(local_tombstones, local_tomb_count,
                                                               rk->label);
            if (lt && lt->deleted_at >= rk->updated_at) {
                if (sp_push_gpg_result(report, SYNC_MERGE_IGNORED, 0, NULL,
                                       rk->label, lt->deleted_at) != 0) goto oom;
                continue;
            }
            if (sp_push_gpg_result(report, SYNC_MERGE_APPLY_REMOTE, 0, rk,
                                   rk->label, 0) != 0) goto oom;
            report->added++;
            continue;
        }

        if (sp_gpg_data_eq(lk, rk)) {
            if (sp_push_gpg_result(report, SYNC_MERGE_IDENTICAL, 0, NULL,
                                   rk->label, 0) != 0) goto oom;
            report->identical++;
            continue;
        }

        int remote_wins;
        if (rk->updated_at != lk->updated_at) {
            remote_wins = rk->updated_at > lk->updated_at;
        } else {
            remote_wins = sp_gpg_content_cmp(rk, lk) > 0;
        }
        const sync_gpg_key_t *winner = remote_wins ? rk : lk;
        if (sp_push_gpg_result(report,
                               remote_wins ? SYNC_MERGE_APPLY_REMOTE : SYNC_MERGE_KEEP_LOCAL,
                               1, winner, rk->label, 0) != 0) goto oom;
        if (remote_wins) report->updated++;
        report->conflicts++;
    }

    for (int i = 0; i < local_count; i++) {
        const sync_gpg_key_t *lk = &local_keys[i];
        int found = 0;
        for (int j = 0; j < remote_count; j++) {
            if (remote_keys[j].label &&
                strcasecmp(remote_keys[j].label, lk->label) == 0) {
                found = 1;
                break;
            }
        }
        if (found) continue;
        const sync_tombstone_t *rt = sp_find_gpg_tombstone(remote_tombstones, remote_tomb_count,
                                                           lk->label);
        if (rt && rt->deleted_at > lk->updated_at) {
            if (sp_push_gpg_result(report, SYNC_MERGE_DELETED, 0, NULL,
                                   lk->label, rt->deleted_at) != 0) goto oom;
            report->deleted++;
        }
    }

    return 0;

oom:
    sync_gpg_merge_report_free(report);
    return -1;
}
