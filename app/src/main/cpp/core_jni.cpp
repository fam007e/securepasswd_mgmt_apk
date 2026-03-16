#include <jni.h>
#include <string> 
#include <android/log.h>
#include <sodium.h>
extern "C" {
#include "core/database.h"
#include "core/password_generator.h"
#include "core/totp.h"
#include "core/sync_service.h"
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

    int result = database_open(path, pass_cstr);
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
    PasswordEntry* entries = database_get_all_entries(&count);

    jclass entryClass = env->FindClass("com/securepasswd/mgmt/PasswordEntry");
    if (!entryClass) return NULL;
    
    // New signature: (I, String, String, [B, [B, [B, I)
    jmethodID constructor = env->GetMethodID(entryClass, "<init>", "(ILjava/lang/String;Ljava/lang/String;[B[B[BI)V");
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
                                        entries[i].pwned_count);
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
        jint pwnedCount) {

    PasswordEntry entry;
    entry.id = 0;
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

    int result = database_add_entry(&entry);
    if (result <= 0) {
        __android_log_print(ANDROID_LOG_ERROR, "CoreInterop", "Failed to add entry: %d", result);
    }

    // entry fields are copied/used by database_add_entry, but we should zero them if they are local copies
    // database_add_entry in this app's core usually strdups if it needs to keep data, 
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
        jint pwnedCount) {

    PasswordEntry entry;
    entry.id = id;
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

    int result = database_update_entry(&entry);
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

    PasswordEntry* entry = database_get_entry_secure(id);
    if (!entry) return NULL;

    jclass entryClass = env->FindClass("com/securepasswd/mgmt/PasswordEntry");
    jmethodID constructor = env->GetMethodID(entryClass, "<init>", "(ILjava/lang/String;Ljava/lang/String;[B[B[BI)V");

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
                                    entry->pwned_count);

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
    return database_delete_entry(id);
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
Java_com_securepasswd_mgmt_CoreInterop_syncEncryptVault(
        JNIEnv* env,
        jobject /* this */,
        jstring source_path,
        jbyteArray key) {
    
    const char *path = env->GetStringUTFChars(source_path, 0);
    jsize key_len = env->GetArrayLength(key);
    jbyte* key_bytes = env->GetByteArrayElements(key, 0);

    if (key_len != SYNC_KEY_LEN) {
        env->ReleaseByteArrayElements(key, key_bytes, 0);
        env->ReleaseStringUTFChars(source_path, path);
        return NULL;
    }

    // Allocate a buffer large enough for encrypted file (file size + overhead)
    // We'll get the file size inside the C service. 
    // For now, let's pre-calculate or handle it better in sync_service.c
    // Actually, sync_service.c can return the size if we pass a pointer.
    
    FILE *f = fopen(path, "rb");
    if (!f) {
        env->ReleaseByteArrayElements(key, key_bytes, 0);
        env->ReleaseStringUTFChars(source_path, path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fclose(f);

    size_t output_size = fsize + SYNC_NONCE_LEN + SYNC_TAG_LEN + 1024; // buffer padding
    unsigned char *output = (unsigned char*)malloc(output_size);
    if (!output) {
        env->ReleaseByteArrayElements(key, key_bytes, 0);
        env->ReleaseStringUTFChars(source_path, path);
        return NULL;
    }

    size_t actual_size = 0;
    if (sync_encrypt_vault(path, output, &actual_size, (unsigned char*)key_bytes) != 0) {
        free(output);
        env->ReleaseByteArrayElements(key, key_bytes, 0);
        env->ReleaseStringUTFChars(source_path, path);
        return NULL;
    }

    jbyteArray result = env->NewByteArray(actual_size);
    env->SetByteArrayRegion(result, 0, actual_size, (jbyte*)output);

    free(output);
    env->ReleaseByteArrayElements(key, key_bytes, 0);
    env->ReleaseStringUTFChars(source_path, path);
    return result;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_securepasswd_mgmt_CoreInterop_syncDecryptVault(
        JNIEnv* env,
        jobject /* this */,
        jbyteArray encrypted_data,
        jstring destination_path,
        jbyteArray key) {
    
    jsize data_len = env->GetArrayLength(encrypted_data);
    jbyte* data_bytes = env->GetByteArrayElements(encrypted_data, 0);
    const char *path = env->GetStringUTFChars(destination_path, 0);
    jsize key_len = env->GetArrayLength(key);
    jbyte* key_bytes = env->GetByteArrayElements(key, 0);

    if (key_len != SYNC_KEY_LEN) {
        env->ReleaseByteArrayElements(key, key_bytes, 0);
        env->ReleaseStringUTFChars(destination_path, path);
        env->ReleaseByteArrayElements(encrypted_data, data_bytes, 0);
        return -1;
    }

    int result = sync_decrypt_vault(
        reinterpret_cast<const unsigned char*>(data_bytes),
        data_len,
        path,
        reinterpret_cast<const unsigned char*>(key_bytes)
    );

    // Securely zero the key bytes before releasing
    if (key_bytes) {
        sodium_memzero(key_bytes, key_len);
    }

    env->ReleaseByteArrayElements(key, key_bytes, 0);
    env->ReleaseStringUTFChars(destination_path, path);
    env->ReleaseByteArrayElements(encrypted_data, data_bytes, 0);
    return result;
}
