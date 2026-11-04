#include <jni.h>
#include <string>
#include <android/log.h>
#include <sodium.h>
extern "C" {
#include "database.h"
#include "password_generator.h"
#include "totp.h"
#include "sync_protocol.h"
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_securepasswd_mgmt_CoreInterop_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "SecurePasswd MGMT Core Loaded";
    return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_securepasswd_mgmt_CoreInterop_databaseOpen(
        JNIEnv* env,
        jobject /* this */,
        jstring db_path,
        jbyteArray password) {
    const char *path = env->GetStringUTFChars(db_path, 0);
    
    jsize pass_len = env->GetArrayLength(password);
    jbyte* pass_bytes = env->GetByteArrayElements(password, 0);
    char* pass_cstr = (char*)malloc(pass_len + 1);
    memcpy(pass_cstr, pass_bytes, pass_len);
    pass_cstr[pass_len] = '\0';

    char salt_path[2048];
    snprintf(salt_path, sizeof(salt_path), "%s.salt", path);

    int result = database_open(path, pass_cstr, salt_path);
    if (result != 0) {
        __android_log_print(ANDROID_LOG_ERROR, "CoreInterop", "Failed to open database: %d", result);
    }

    sodium_memzero(pass_cstr, pass_len);
    free(pass_cstr);
    sodium_memzero(pass_bytes, pass_len);
    env->ReleaseByteArrayElements(password, pass_bytes, JNI_ABORT);
    env->ReleaseStringUTFChars(db_path, path);
    return result;
}

extern "C" JNIEXPORT void JNICALL
Java_com_securepasswd_mgmt_CoreInterop_databaseClose(
        JNIEnv* env,
        jobject /* this */) {
    database_close();
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_securepasswd_mgmt_CoreInterop_databaseGetAllEntries(
        JNIEnv* env,
        jobject /* this */) {
    int count = 0;
    PasswordEntry* entries = database_get_all(&count);

    jclass entryClass = env->FindClass("com/securepasswd/mgmt/PasswordEntry");
    if (!entryClass) return NULL;
    
    // New signature: (I, String, String, [B, [B, [B, I)
    jmethodID constructor = env->GetMethodID(entryClass, "<init>", "(ILjava/lang/String;Ljava/lang/String;[B[B[BIJ)V");
    if (!constructor) return NULL;

    jobjectArray array = env->NewObjectArray(count, entryClass, NULL);
    if (!array) return NULL;

    for (int i = 0; i < count; i++) {
        jstring service = env->NewStringUTF(entries[i].service ? entries[i].service : "");
        jstring username = env->NewStringUTF(entries[i].username ? entries[i].username : "");
        
        // Return password as byte array for health check
        size_t pass_len = entries[i].password ? strlen(entries[i].password) : 0;
        jbyteArray password = env->NewByteArray(pass_len);
        if (pass_len > 0) {
            env->SetByteArrayRegion(password, 0, pass_len, (jbyte*)entries[i].password);
        }

        // Empty byte arrays for TOTP and Recovery in list view
        jbyteArray emptyTotp = env->NewByteArray(0);
        jbyteArray emptyRecovery = env->NewByteArray(0);

        jobject entryObj = env->NewObject(entryClass, constructor,
                                        entries[i].id,
                                        service,
                                        username,
                                        password,
                                        emptyTotp,
                                        emptyRecovery,
                                        entries[i].pwned_count,
                                        (jlong)entries[i].updated_at);
        env->SetObjectArrayElement(array, i, entryObj);
        env->DeleteLocalRef(service);
        env->DeleteLocalRef(username);
        env->DeleteLocalRef(password);
        env->DeleteLocalRef(emptyTotp);
        env->DeleteLocalRef(emptyRecovery);
        env->DeleteLocalRef(entryObj);
    }

    free_password_entries(entries, count);
    return array;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_securepasswd_mgmt_CoreInterop_generateTotp(
        JNIEnv* env,
        jobject /* this */,
        jbyteArray secret) {
    jsize sec_len = env->GetArrayLength(secret);
    jbyte* sec_bytes = env->GetByteArrayElements(secret, 0);
    char* sec_cstr = (char*)malloc(sec_len + 1);
    memcpy(sec_cstr, sec_bytes, sec_len);
    sec_cstr[sec_len] = '\0';

    char* code = generate_totp_code(sec_cstr);

    sodium_memzero(sec_cstr, sec_len);
    free(sec_cstr);
    env->ReleaseByteArrayElements(secret, sec_bytes, JNI_ABORT);

    if (code) {
        size_t code_len = strlen(code);
        jbyteArray result = env->NewByteArray(code_len);
        env->SetByteArrayRegion(result, 0, code_len, (jbyte*)code);
        sodium_memzero(code, code_len);
        free(code);
        return result;
    }
    return env->NewByteArray(0);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_securepasswd_mgmt_CoreInterop_databaseAddEntry(
        JNIEnv* env,
        jobject /* this */,
        jstring service,
        jstring username,
        jbyteArray password,
        jbyteArray totpSecret,
        jbyteArray recoveryCodes,
        jint pwnedCount,
        jlong updatedAt) {

    PasswordEntry entry;
    entry.id = 0;
    entry.updated_at = (long long)updatedAt;
    entry.service = (char*)env->GetStringUTFChars(service, 0);
    entry.username = (char*)env->GetStringUTFChars(username, 0);
    
    jsize pass_len = env->GetArrayLength(password);
    jbyte* pass_bytes = env->GetByteArrayElements(password, 0);
    entry.password = (char*)malloc(pass_len + 1);
    memcpy(entry.password, pass_bytes, pass_len);
    entry.password[pass_len] = '\0';

    jsize totp_len = env->GetArrayLength(totpSecret);
    jbyte* totp_bytes = env->GetByteArrayElements(totpSecret, 0);
    entry.totp_secret = (char*)malloc(totp_len + 1);
    memcpy(entry.totp_secret, totp_bytes, totp_len);
    entry.totp_secret[totp_len] = '\0';

    jsize recovery_len = env->GetArrayLength(recoveryCodes);
    jbyte* recovery_bytes = env->GetByteArrayElements(recoveryCodes, 0);
    entry.recovery_codes = (char*)malloc(recovery_len + 1);
    memcpy(entry.recovery_codes, recovery_bytes, recovery_len);
    entry.recovery_codes[recovery_len] = '\0';

    entry.pwned_count = pwnedCount;

    int result = database_add(&entry);
    if (result <= 0) {
        __android_log_print(ANDROID_LOG_ERROR, "CoreInterop", "Failed to add entry: %d", result);
    }

    // entry fields are copied/used by database_add, but we should zero them if they are local copies
    // database_add in this app's core usually strdups if it needs to keep data, 
    // but here we allocated them ourselves to pass to the core.
    
    env->ReleaseStringUTFChars(service, entry.service);
    env->ReleaseStringUTFChars(username, entry.username);
    
    sodium_memzero(entry.password, pass_len);
    free(entry.password);
    env->ReleaseByteArrayElements(password, pass_bytes, JNI_ABORT);

    sodium_memzero(entry.totp_secret, totp_len);
    free(entry.totp_secret);
    env->ReleaseByteArrayElements(totpSecret, totp_bytes, JNI_ABORT);

    sodium_memzero(entry.recovery_codes, recovery_len);
    free(entry.recovery_codes);
    env->ReleaseByteArrayElements(recoveryCodes, recovery_bytes, JNI_ABORT);

    return result;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_securepasswd_mgmt_CoreInterop_databaseUpdateEntry(
        JNIEnv* env,
        jobject /* this */,
        jint id,
        jstring service,
        jstring username,
        jbyteArray password,
        jbyteArray totpSecret,
        jbyteArray recoveryCodes,
        jint pwnedCount,
        jlong updatedAt) {

    PasswordEntry entry;
    entry.id = id;
    entry.updated_at = (long long)updatedAt;
    entry.service = (char*)env->GetStringUTFChars(service, 0);
    entry.username = (char*)env->GetStringUTFChars(username, 0);
    
    jsize pass_len = env->GetArrayLength(password);
    jbyte* pass_bytes = env->GetByteArrayElements(password, 0);
    entry.password = (char*)malloc(pass_len + 1);
    memcpy(entry.password, pass_bytes, pass_len);
    entry.password[pass_len] = '\0';

    jsize totp_len = env->GetArrayLength(totpSecret);
    jbyte* totp_bytes = env->GetByteArrayElements(totpSecret, 0);
    entry.totp_secret = (char*)malloc(totp_len + 1);
    memcpy(entry.totp_secret, totp_bytes, totp_len);
    entry.totp_secret[totp_len] = '\0';

    jsize recovery_len = env->GetArrayLength(recoveryCodes);
    jbyte* recovery_bytes = env->GetByteArrayElements(recoveryCodes, 0);
    entry.recovery_codes = (char*)malloc(recovery_len + 1);
    memcpy(entry.recovery_codes, recovery_bytes, recovery_len);
    entry.recovery_codes[recovery_len] = '\0';

    entry.pwned_count = pwnedCount;

    int result = database_update(&entry);
    if (result != 0) {
        __android_log_print(ANDROID_LOG_ERROR, "CoreInterop", "Failed to update entry: %d", result);
    }

    env->ReleaseStringUTFChars(service, entry.service);
    env->ReleaseStringUTFChars(username, entry.username);
    
    sodium_memzero(entry.password, pass_len);
    free(entry.password);
    env->ReleaseByteArrayElements(password, pass_bytes, JNI_ABORT);

    sodium_memzero(entry.totp_secret, totp_len);
    free(entry.totp_secret);
    env->ReleaseByteArrayElements(totpSecret, totp_bytes, JNI_ABORT);

    sodium_memzero(entry.recovery_codes, recovery_len);
    free(entry.recovery_codes);
    env->ReleaseByteArrayElements(recoveryCodes, recovery_bytes, JNI_ABORT);

    return result;
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_securepasswd_mgmt_CoreInterop_databaseGetEntry(
        JNIEnv* env,
        jobject /* this */,
        jint id) {

    PasswordEntry* entry = database_get_by_id(id);
    if (!entry) return NULL;

    jclass entryClass = env->FindClass("com/securepasswd/mgmt/PasswordEntry");
    jmethodID constructor = env->GetMethodID(entryClass, "<init>", "(ILjava/lang/String;Ljava/lang/String;[B[B[BIJ)V");

    jstring service = env->NewStringUTF(entry->service ? entry->service : "");
    jstring username = env->NewStringUTF(entry->username ? entry->username : "");
    
    size_t pass_len = entry->password ? strlen(entry->password) : 0;
    jbyteArray password = env->NewByteArray(pass_len);
    if (pass_len > 0) env->SetByteArrayRegion(password, 0, pass_len, (jbyte*)entry->password);

    size_t totp_len = entry->totp_secret ? strlen(entry->totp_secret) : 0;
    jbyteArray totpSecret = env->NewByteArray(totp_len);
    if (totp_len > 0) env->SetByteArrayRegion(totpSecret, 0, totp_len, (jbyte*)entry->totp_secret);

    size_t recovery_len = entry->recovery_codes ? strlen(entry->recovery_codes) : 0;
    jbyteArray recoveryCodes = env->NewByteArray(recovery_len);
    if (recovery_len > 0) env->SetByteArrayRegion(recoveryCodes, 0, recovery_len, (jbyte*)entry->recovery_codes);

    jobject entryObj = env->NewObject(entryClass, constructor,
                                    entry->id,
                                    service,
                                    username,
                                    password,
                                    totpSecret,
                                    recoveryCodes,
                                    entry->pwned_count,
                                    (jlong)entry->updated_at);

    free_password_entries(entry, 1);
    return entryObj;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_securepasswd_mgmt_CoreInterop_databaseUpdatePwnedCount(
        JNIEnv* env,
        jobject /* this */,
        jint id,
        jint pwnedCount) {
    int result = database_update_pwned_count(id, pwnedCount);
    if (result != 0) {
        __android_log_print(ANDROID_LOG_ERROR, "CoreInterop", "Failed to update pwned count: %d", result);
    }
    return result;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_securepasswd_mgmt_CoreInterop_databaseDeleteEntry(
        JNIEnv* env,
        jobject /* this */,
        jint id) {
    return database_delete(id);
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_securepasswd_mgmt_CoreInterop_generatePassword(
        JNIEnv* env,
        jobject /* this */,
        jint length,
        jboolean useUpper,
        jboolean useNum,
        jboolean useSpecial) {
    
    char* pass = generate_password(length, useUpper, useNum, useSpecial);
    if (pass) {
        size_t pass_len = strlen(pass);
        jbyteArray result = env->NewByteArray(pass_len);
        env->SetByteArrayRegion(result, 0, pass_len, (jbyte*)pass);
        sodium_memzero(pass, pass_len);
        free(pass);
        return result;
    }
    return env->NewByteArray(0);
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_securepasswd_mgmt_CoreInterop_syncEphemeralKeygen(
        JNIEnv* env,
        jobject /* this */) {
    uint8_t pub[SYNC_EPHEMERAL_LEN];
    uint8_t priv[SYNC_EPHEMERAL_LEN];
    if (sync_ephemeral_keygen(pub, priv) != 0) {
        return NULL;
    }
    jbyteArray result = env->NewByteArray(SYNC_EPHEMERAL_LEN * 2);
    jbyte combined[SYNC_EPHEMERAL_LEN * 2];
    memcpy(combined, pub, SYNC_EPHEMERAL_LEN);
    memcpy(combined + SYNC_EPHEMERAL_LEN, priv, SYNC_EPHEMERAL_LEN);
    env->SetByteArrayRegion(result, 0, SYNC_EPHEMERAL_LEN * 2, combined);
    sodium_memzero(combined, sizeof(combined));
    sodium_memzero(priv, sizeof(priv));
    return result;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_securepasswd_mgmt_CoreInterop_syncSessionDerive(
        JNIEnv* env,
        jobject /* this */,
        jint role,
        jbyteArray psk,
        jbyteArray clientPub,
        jbyteArray serverPub,
        jbyteArray ownPriv) {
    if (env->GetArrayLength(psk) != SYNC_PSK_LEN ||
        env->GetArrayLength(clientPub) != SYNC_EPHEMERAL_LEN ||
        env->GetArrayLength(serverPub) != SYNC_EPHEMERAL_LEN ||
        env->GetArrayLength(ownPriv) != SYNC_EPHEMERAL_LEN) {
        return 0;
    }

    jbyte* psk_b = env->GetByteArrayElements(psk, 0);
    jbyte* cpub_b = env->GetByteArrayElements(clientPub, 0);
    jbyte* spub_b = env->GetByteArrayElements(serverPub, 0);
    jbyte* opriv_b = env->GetByteArrayElements(ownPriv, 0);

    sync_session_t* session = (sync_session_t*)malloc(sizeof(sync_session_t));
    int rc = -1;
    if (session) {
        rc = sync_session_derive(
            (role == 0) ? SYNC_ROLE_SERVER : SYNC_ROLE_CLIENT,
            reinterpret_cast<const uint8_t*>(psk_b),
            reinterpret_cast<const uint8_t*>(cpub_b),
            reinterpret_cast<const uint8_t*>(spub_b),
            reinterpret_cast<const uint8_t*>(opriv_b),
            session);
    }

    env->ReleaseByteArrayElements(psk, psk_b, JNI_ABORT);
    env->ReleaseByteArrayElements(clientPub, cpub_b, JNI_ABORT);
    env->ReleaseByteArrayElements(serverPub, spub_b, JNI_ABORT);
    env->ReleaseByteArrayElements(ownPriv, opriv_b, JNI_ABORT);

    if (rc != 0) {
        free(session);
        return 0;
    }
    return reinterpret_cast<jlong>(session);
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_securepasswd_mgmt_CoreInterop_syncFrameEncrypt(
        JNIEnv* env,
        jobject /* this */,
        jlong handle,
        jint type,
        jbyteArray payload) {
    sync_session_t* session = reinterpret_cast<sync_session_t*>(handle);
    if (!session) return NULL;

    jsize len = env->GetArrayLength(payload);
    jbyte* bytes = env->GetByteArrayElements(payload, 0);

    size_t out_cap = 5 + (size_t)len + SYNC_TAG_LEN + 16;
    unsigned char* out = (unsigned char*)malloc(out_cap);
    size_t out_len = 0;
    jbyteArray result = NULL;
    if (out && sync_frame_encrypt(session, (uint8_t)type,
                                  reinterpret_cast<const uint8_t*>(bytes), (size_t)len,
                                  out, out_cap, &out_len) == 0) {
        result = env->NewByteArray((jsize)out_len);
        env->SetByteArrayRegion(result, 0, (jsize)out_len, (jbyte*)out);
    }
    free(out);
    env->ReleaseByteArrayElements(payload, bytes, JNI_ABORT);
    return result;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_securepasswd_mgmt_CoreInterop_syncFrameDecrypt(
        JNIEnv* env,
        jobject /* this */,
        jlong handle,
        jint expectedType,
        jbyteArray frame) {
    sync_session_t* session = reinterpret_cast<sync_session_t*>(handle);
    if (!session) return NULL;

    jsize len = env->GetArrayLength(frame);
    if (len < 5 + SYNC_TAG_LEN) return NULL;
    jbyte* bytes = env->GetByteArrayElements(frame, 0);

    size_t payload_cap = (size_t)len; /* >= ciphertext length, always enough */
    unsigned char* out = (unsigned char*)malloc(payload_cap);
    size_t out_len = 0;
    jbyteArray result = NULL;
    if (out && sync_frame_decrypt(session, (uint8_t)expectedType,
                                  reinterpret_cast<const uint8_t*>(bytes), (size_t)len,
                                  out, payload_cap, &out_len) == 0) {
        result = env->NewByteArray((jsize)out_len);
        env->SetByteArrayRegion(result, 0, (jsize)out_len, (jbyte*)out);
        sodium_memzero(out, out_len);
    }
    free(out);
    env->ReleaseByteArrayElements(frame, bytes, JNI_ABORT);
    return result;
}

extern "C" JNIEXPORT void JNICALL
Java_com_securepasswd_mgmt_CoreInterop_syncSessionFree(
        JNIEnv* env,
        jobject /* this */,
        jlong handle) {
    sync_session_t* session = reinterpret_cast<sync_session_t*>(handle);
    if (session) {
        sync_session_zero(session);
        free(session);
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_securepasswd_mgmt_CoreInterop_syncGetTranscriptHash(
        JNIEnv* env,
        jobject /* this */,
        jlong handle) {
    sync_session_t* session = reinterpret_cast<sync_session_t*>(handle);
    if (!session) return NULL;
    jbyteArray result = env->NewByteArray(32);
    env->SetByteArrayRegion(result, 0, 32, (jbyte*)session->transcript_hash);
    return result;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_securepasswd_mgmt_CoreInterop_syncBuildLocalSnapshot(
        JNIEnv* env,
        jobject /* this */) {
    int entry_count = 0;
    int tomb_count = 0;
    PasswordEntry* db_entries = database_get_all(&entry_count);
    sync_tombstone_t* tombs = database_get_tombstones(&tomb_count);

    jbyteArray result = NULL;
    uint8_t* buf = NULL;
    size_t buf_len = 0;

    // PasswordEntry and sync_entry_t have different layouts (id, pwned_count);
    // convert field by field instead of casting.
    sync_entry_t* entries = (sync_entry_t*)calloc((size_t)(entry_count ? entry_count : 1), sizeof(sync_entry_t));
    if (entries) {
        for (int i = 0; i < entry_count; i++) {
            entries[i].service = strdup(db_entries[i].service ? db_entries[i].service : "");
            entries[i].username = strdup(db_entries[i].username ? db_entries[i].username : "");
            entries[i].password = strdup(db_entries[i].password ? db_entries[i].password : "");
            entries[i].totp_secret = strdup(db_entries[i].totp_secret ? db_entries[i].totp_secret : "");
            entries[i].recovery_codes = strdup(db_entries[i].recovery_codes ? db_entries[i].recovery_codes : "");
            entries[i].updated_at = (int64_t)db_entries[i].updated_at;
        }
        if (sync_snapshot_serialize(entries, entry_count, tombs, tomb_count, &buf, &buf_len) == 0 && buf) {
            result = env->NewByteArray((jsize)buf_len);
            env->SetByteArrayRegion(result, 0, (jsize)buf_len, (jbyte*)buf);
            memset(buf, 0, buf_len);
            free(buf);
        }
        sync_entries_free(entries, entry_count);
    }

    if (db_entries) free_password_entries(db_entries, entry_count);
    if (tombs) sync_tombstones_free(tombs, tomb_count);
    return result;
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_securepasswd_mgmt_CoreInterop_syncGetLocalTombstones(
        JNIEnv* env,
        jobject /* this */) {
    int count = 0;
    sync_tombstone_t* tombs = database_get_tombstones(&count);

    jclass tombClass = env->FindClass("com/securepasswd/mgmt/SyncTombstone");
    if (!tombClass) {
        sync_tombstones_free(tombs, count);
        return NULL;
    }
    jmethodID ctor = env->GetMethodID(tombClass, "<init>", "(Ljava/lang/String;Ljava/lang/String;J)V");
    jobjectArray arr = env->NewObjectArray(count, tombClass, NULL);
    if (!ctor || !arr) {
        sync_tombstones_free(tombs, count);
        return arr;
    }
    for (int i = 0; i < count; i++) {
        jstring s = env->NewStringUTF(tombs[i].service ? tombs[i].service : "");
        jstring u = env->NewStringUTF(tombs[i].username ? tombs[i].username : "");
        jobject t = env->NewObject(tombClass, ctor, s, u, (jlong)tombs[i].deleted_at);
        env->SetObjectArrayElement(arr, i, t);
        env->DeleteLocalRef(s); env->DeleteLocalRef(u); env->DeleteLocalRef(t);
    }
    sync_tombstones_free(tombs, count);
    return arr;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_securepasswd_mgmt_CoreInterop_syncPackSnapshot(
        JNIEnv* env,
        jobject /* this */,
        jobjectArray services,
        jobjectArray usernames,
        jobjectArray passwords,
        jobjectArray totpSecrets,
        jobjectArray recoveryCodes,
        jlongArray updatedAts,
        jobjectArray tombServices,
        jobjectArray tombUsernames,
        jlongArray tombTimes) {
    int entry_count = services ? env->GetArrayLength(services) : 0;
    int tomb_count = tombServices ? env->GetArrayLength(tombServices) : 0;

    sync_entry_t* entries = (sync_entry_t*)calloc((size_t)(entry_count ? entry_count : 1), sizeof(sync_entry_t));
    sync_tombstone_t* tombs = (sync_tombstone_t*)calloc((size_t)(tomb_count ? tomb_count : 1), sizeof(sync_tombstone_t));
    if (!entries || !tombs) {
        free(entries); free(tombs);
        return NULL;
    }

    jlong* ats = updatedAts ? env->GetLongArrayElements(updatedAts, 0) : NULL;
    jlong* tts = tombTimes ? env->GetLongArrayElements(tombTimes, 0) : NULL;

    for (int i = 0; i < entry_count; i++) {
        jstring s = (jstring)env->GetObjectArrayElement(services, i);
        jstring u = (jstring)env->GetObjectArrayElement(usernames, i);
        jbyteArray p = (jbyteArray)env->GetObjectArrayElement(passwords, i);
        jbyteArray t = (jbyteArray)env->GetObjectArrayElement(totpSecrets, i);
        jbyteArray r = (jbyteArray)env->GetObjectArrayElement(recoveryCodes, i);
        const char* sc = s ? env->GetStringUTFChars(s, 0) : "";
        const char* uc = u ? env->GetStringUTFChars(u, 0) : "";
        entries[i].service = strdup(sc ? sc : "");
        entries[i].username = strdup(uc ? uc : "");
        if (s) env->ReleaseStringUTFChars(s, sc);
        if (u) env->ReleaseStringUTFChars(u, uc);
        auto copyBytes = [&](jbyteArray arr) -> char* {
            if (!arr) return strdup("");
            jsize n = env->GetArrayLength(arr);
            jbyte* b = env->GetByteArrayElements(arr, 0);
            char* c = (char*)malloc((size_t)n + 1);
            if (c) { memcpy(c, b, (size_t)n); c[n] = '\0'; }
            env->ReleaseByteArrayElements(arr, b, JNI_ABORT);
            return c ? c : strdup("");
        };
        entries[i].password = copyBytes(p);
        entries[i].totp_secret = copyBytes(t);
        entries[i].recovery_codes = copyBytes(r);
        entries[i].updated_at = ats ? (int64_t)ats[i] : 0;
        env->DeleteLocalRef(s); env->DeleteLocalRef(u);
        env->DeleteLocalRef(p); env->DeleteLocalRef(t); env->DeleteLocalRef(r);
    }

    for (int i = 0; i < tomb_count; i++) {
        jstring s = (jstring)env->GetObjectArrayElement(tombServices, i);
        jstring u = (jstring)env->GetObjectArrayElement(tombUsernames, i);
        const char* sc = s ? env->GetStringUTFChars(s, 0) : "";
        const char* uc = u ? env->GetStringUTFChars(u, 0) : "";
        tombs[i].service = strdup(sc ? sc : "");
        tombs[i].username = strdup(uc ? uc : "");
        if (s) env->ReleaseStringUTFChars(s, sc);
        if (u) env->ReleaseStringUTFChars(u, uc);
        tombs[i].deleted_at = tts ? (int64_t)tts[i] : 0;
        env->DeleteLocalRef(s); env->DeleteLocalRef(u);
    }

    if (ats) env->ReleaseLongArrayElements(updatedAts, ats, JNI_ABORT);
    if (tts) env->ReleaseLongArrayElements(tombTimes, tts, JNI_ABORT);

    uint8_t* buf = NULL;
    size_t buf_len = 0;
    jbyteArray result = NULL;
    if (sync_snapshot_serialize(entries, entry_count, tombs, tomb_count, &buf, &buf_len) == 0 && buf) {
        result = env->NewByteArray((jsize)buf_len);
        env->SetByteArrayRegion(result, 0, (jsize)buf_len, (jbyte*)buf);
        memset(buf, 0, buf_len);
        free(buf);
    }

    sync_entries_free(entries, entry_count);
    sync_tombstones_free(tombs, tomb_count);
    return result;
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_securepasswd_mgmt_CoreInterop_syncUnpackSnapshot(
        JNIEnv* env,
        jobject /* this */,
        jbyteArray data) {
    jsize len = env->GetArrayLength(data);
    jbyte* bytes = env->GetByteArrayElements(data, 0);

    sync_entry_t* entries = NULL;
    sync_tombstone_t* tombs = NULL;
    int entry_count = 0, tomb_count = 0;
    int rc = sync_snapshot_deserialize(reinterpret_cast<const uint8_t*>(bytes), (size_t)len,
                                       &entries, &entry_count, &tombs, &tomb_count);
    env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
    if (rc != 0) return NULL;

    jclass entryClass = env->FindClass("com/securepasswd/mgmt/PasswordEntry");
    jclass tombClass = env->FindClass("com/securepasswd/mgmt/SyncTombstone");
    jclass snapClass = env->FindClass("com/securepasswd/mgmt/SyncSnapshot");
    if (!entryClass || !tombClass || !snapClass) {
        sync_entries_free(entries, entry_count);
        sync_tombstones_free(tombs, tomb_count);
        return NULL;
    }
    jmethodID entryCtor = env->GetMethodID(entryClass, "<init>",
        "(ILjava/lang/String;Ljava/lang/String;[B[B[BIJ)V");
    jmethodID tombCtor = env->GetMethodID(tombClass, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;J)V");
    jmethodID snapCtor = env->GetMethodID(snapClass, "<init>",
        "([Lcom/securepasswd/mgmt/PasswordEntry;[Lcom/securepasswd/mgmt/SyncTombstone;)V");
    if (!entryCtor || !tombCtor || !snapCtor) {
        sync_entries_free(entries, entry_count);
        sync_tombstones_free(tombs, tomb_count);
        return NULL;
    }

    jobjectArray jentries = env->NewObjectArray(entry_count, entryClass, NULL);
    for (int i = 0; i < entry_count; i++) {
        jstring s = env->NewStringUTF(entries[i].service ? entries[i].service : "");
        jstring u = env->NewStringUTF(entries[i].username ? entries[i].username : "");
        auto mkBytes = [&](const char* c) -> jbyteArray {
            size_t n = c ? strlen(c) : 0;
            jbyteArray arr = env->NewByteArray((jsize)n);
            if (n) env->SetByteArrayRegion(arr, 0, (jsize)n, (jbyte*)c);
            return arr;
        };
        jbyteArray p = mkBytes(entries[i].password);
        jbyteArray t = mkBytes(entries[i].totp_secret);
        jbyteArray r = mkBytes(entries[i].recovery_codes);
        jobject e = env->NewObject(entryClass, entryCtor, 0, s, u, p, t, r, -1,
                                   (jlong)entries[i].updated_at);
        env->SetObjectArrayElement(jentries, i, e);
        env->DeleteLocalRef(s); env->DeleteLocalRef(u);
        env->DeleteLocalRef(p); env->DeleteLocalRef(t); env->DeleteLocalRef(r);
        env->DeleteLocalRef(e);
    }

    jobjectArray jtombs = env->NewObjectArray(tomb_count, tombClass, NULL);
    for (int i = 0; i < tomb_count; i++) {
        jstring s = env->NewStringUTF(tombs[i].service ? tombs[i].service : "");
        jstring u = env->NewStringUTF(tombs[i].username ? tombs[i].username : "");
        jobject t = env->NewObject(tombClass, tombCtor, s, u, (jlong)tombs[i].deleted_at);
        env->SetObjectArrayElement(jtombs, i, t);
        env->DeleteLocalRef(s); env->DeleteLocalRef(u);
        env->DeleteLocalRef(t);
    }

    jobject snapshot = env->NewObject(snapClass, snapCtor, jentries, jtombs);

    sync_entries_free(entries, entry_count);
    sync_tombstones_free(tombs, tomb_count);
    return snapshot;
}
