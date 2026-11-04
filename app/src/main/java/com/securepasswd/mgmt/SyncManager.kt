package com.securepasswd.mgmt

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Arrays

sealed class SyncResult {
    data class Success(val additions: Int, val updates: Int, val deletions: Int) : SyncResult()
    data class Failure(val message: String) : SyncResult()
}

object SyncManager {
    private const val TAG = "SyncManager"
    private const val CONNECT_TIMEOUT_MS = 10000
    private const val SOCKET_TIMEOUT_MS = 20000
    private const val PROTOCOL_VERSION: Byte = 0x02

    suspend fun performSync(
        context: Context,
        ip: String,
        port: Int,
        psk: ByteArray,
        onProgress: (String) -> Unit
    ): SyncResult = withContext(Dispatchers.IO) {
        var sessionHandle: Long = 0L
        var clientPriv: ByteArray? = null
        var keypair: ByteArray? = null

        try {
            onProgress("Connecting to $ip:$port...")
            Log.d(TAG, "Connecting to $ip:$port")

            Socket().use { socket ->
                socket.soTimeout = SOCKET_TIMEOUT_MS
                socket.connect(InetSocketAddress(ip, port), CONNECT_TIMEOUT_MS)
                val out: OutputStream = socket.getOutputStream()
                val inp: InputStream = socket.getInputStream()

                onProgress("Connected. Performing cryptographic handshake...")
                // Generate ephemeral X25519 keypair (64 bytes: 32 pub + 32 priv)
                keypair = CoreInterop.syncEphemeralKeygen()
                    ?: return@withContext SyncResult.Failure("Failed to generate ephemeral keys")
                val clientPub = keypair!!.copyOfRange(0, 32)
                clientPriv = keypair!!.copyOfRange(32, 64)

                // 1. Send Client Hello: [0x02 (1 byte), clientPub (32 bytes)]
                val clientHello = ByteArray(33)
                clientHello[0] = PROTOCOL_VERSION
                System.arraycopy(clientPub, 0, clientHello, 1, 32)
                out.write(clientHello)
                out.flush()

                // 2. Read Server Hello: [0x02 (1 byte), serverPub (32 bytes)]
                val serverHello = readExact(inp, 33)
                if (serverHello[0] != PROTOCOL_VERSION) {
                    return@withContext SyncResult.Failure("Incompatible desktop protocol version: ${serverHello[0]}")
                }
                val serverPub = serverHello.copyOfRange(1, 33)

                // 3. Derive AEAD session keys with PSK + X25519 shared secret
                sessionHandle = CoreInterop.syncSessionDerive(
                    role = 1, // CLIENT
                    psk = psk,
                    clientPub = clientPub,
                    serverPub = serverPub,
                    ownPriv = clientPriv!!
                )
                if (sessionHandle == 0L) {
                    return@withContext SyncResult.Failure("Failed to establish secure session (key derivation error)")
                }

                // 4. Key confirmation exchange
                onProgress("Verifying mutual authentication...")
                // Server sends CONFIRM first
                val (serverFrameType, serverConfirmFrame) = readFrame(inp)
                if (serverFrameType != CoreInterop.FRAME_CONFIRM) {
                    return@withContext SyncResult.Failure("Protocol error: expected CONFIRM frame (got 0x${serverFrameType.toString(16)})")
                }
                val serverConfirmPayload = CoreInterop.syncFrameDecrypt(
                    sessionHandle,
                    CoreInterop.FRAME_CONFIRM,
                    serverConfirmFrame
                ) ?: return@withContext SyncResult.Failure("Authentication failed: invalid pairing key or corrupted data")

                val localTranscript = CoreInterop.syncGetTranscriptHash(sessionHandle)
                    ?: return@withContext SyncResult.Failure("Failed to compute transcript hash")

                if (!Arrays.equals(serverConfirmPayload, localTranscript)) {
                    return@withContext SyncResult.Failure("Key confirmation mismatch: desktop pairing key does not match")
                }

                // Client sends its CONFIRM frame
                val clientConfirmFrame = CoreInterop.syncFrameEncrypt(
                    sessionHandle,
                    CoreInterop.FRAME_CONFIRM,
                    localTranscript
                ) ?: return@withContext SyncResult.Failure("Failed to encrypt confirmation frame")
                out.write(clientConfirmFrame)
                out.flush()

                // 5. Send local vault snapshot to server
                onProgress("Sending local vault snapshot...")
                val localSnapshot = CoreInterop.syncBuildLocalSnapshot()
                    ?: return@withContext SyncResult.Failure("Failed to serialize local vault")

                val snapshotFrame = CoreInterop.syncFrameEncrypt(
                    sessionHandle,
                    CoreInterop.FRAME_SNAPSHOT,
                    localSnapshot
                )
                localSnapshot.fill(0)
                if (snapshotFrame == null) {
                    return@withContext SyncResult.Failure("Failed to encrypt vault snapshot")
                }
                out.write(snapshotFrame)
                out.flush()

                // 6. Receive merged snapshot from server
                onProgress("Waiting for server merge...")
                val (mergedFrameType, mergedFrame) = readFrame(inp)
                if (mergedFrameType != CoreInterop.FRAME_SNAPSHOT) {
                    return@withContext SyncResult.Failure("Protocol error: expected SNAPSHOT frame (got 0x${mergedFrameType.toString(16)})")
                }
                val mergedBytes = CoreInterop.syncFrameDecrypt(
                    sessionHandle,
                    CoreInterop.FRAME_SNAPSHOT,
                    mergedFrame
                ) ?: return@withContext SyncResult.Failure("Failed to decrypt merged vault")

                val mergedSnapshot = CoreInterop.syncUnpackSnapshot(mergedBytes)
                mergedBytes.fill(0)
                if (mergedSnapshot == null) {
                    return@withContext SyncResult.Failure("Failed to deserialize merged vault")
                }

                // 7. Apply merged changes to the local vault
                onProgress("Applying merged changes...")
                val currentEntries = CoreInterop.databaseGetAllEntries()?.toList() ?: emptyList()
                val currentMap = currentEntries.associateBy {
                    "${it.service.lowercase()}:${it.username.lowercase()}"
                }

                var additions = 0
                var updates = 0
                var deletions = 0

                // Add or update entries from the merged snapshot
                for (entry in mergedSnapshot.entries) {
                    val identity = "${entry.service.lowercase()}:${entry.username.lowercase()}"
                    val existing = currentMap[identity]
                    if (existing == null) {
                        val rc = CoreInterop.databaseAddEntry(
                            entry.service,
                            entry.username,
                            entry.password,
                            entry.totpSecret,
                            entry.recoveryCodes,
                            entry.pwnedCount,
                            entry.updatedAt
                        )
                        if (rc > 0) additions++
                    } else if (!isDataIdentical(existing, entry)) {
                        val rc = CoreInterop.databaseUpdateEntry(
                            existing.id,
                            entry.service,
                            entry.username,
                            entry.password,
                            entry.totpSecret,
                            entry.recoveryCodes,
                            entry.pwnedCount,
                            entry.updatedAt
                        )
                        if (rc == 0) updates++
                    }
                }

                // Apply deletions based on tombstones
                for (tomb in mergedSnapshot.tombstones) {
                    val identity = "${tomb.service.lowercase()}:${tomb.username.lowercase()}"
                    val existing = currentMap[identity]
                    if (existing != null && existing.updatedAt <= tomb.deletedAt) {
                        val rc = CoreInterop.databaseDeleteEntry(existing.id)
                        if (rc == 0) deletions++
                    }
                }

                // Wipe memory of incoming decrypted entries
                mergedSnapshot.wipe()

                // 8. Send ACK frame to desktop to conclude the session
                onProgress("Finalizing sync...")
                val ackFrame = CoreInterop.syncFrameEncrypt(
                    sessionHandle,
                    CoreInterop.FRAME_ACK,
                    ByteArray(0)
                )
                if (ackFrame != null) {
                    out.write(ackFrame)
                    out.flush()
                }

                onProgress("Two-way sync complete!")
                return@withContext SyncResult.Success(additions, updates, deletions)
            }
        } catch (e: java.net.SocketTimeoutException) {
            Log.e(TAG, "Sync timeout", e)
            return@withContext SyncResult.Failure("Connection timed out. Check firewall and ensure both devices are on the same network.")
        } catch (e: java.net.ConnectException) {
            Log.e(TAG, "Connection refused", e)
            return@withContext SyncResult.Failure("Connection refused by $ip:$port. Ensure Desktop sync is active.")
        } catch (e: Exception) {
            Log.e(TAG, "Sync error", e)
            return@withContext SyncResult.Failure("Sync error: ${e.message ?: "Unknown error"}")
        } finally {
            if (sessionHandle != 0L) {
                CoreInterop.syncSessionFree(sessionHandle)
            }
            clientPriv?.fill(0)
            keypair?.fill(0)
            psk.fill(0)
        }
    }

    private fun isDataIdentical(local: PasswordEntry, incoming: PasswordEntry): Boolean {
        return local.password.contentEquals(incoming.password) &&
                local.totpSecret.contentEquals(incoming.totpSecret) &&
                local.recoveryCodes.contentEquals(incoming.recoveryCodes)
    }

    private fun readExact(inp: InputStream, count: Int): ByteArray {
        val buf = ByteArray(count)
        var read = 0
        while (read < count) {
            val n = inp.read(buf, read, count - read)
            if (n < 0) throw EOFException("Premature end of stream while reading $count bytes (read $read)")
            read += n
        }
        return buf
    }

    private fun readFrame(inp: InputStream): Pair<Int, ByteArray> {
        val header = readExact(inp, 5)
        val type = header[0].toInt() and 0xFF
        val ctLen = ((header[1].toInt() and 0xFF) shl 24) or
                ((header[2].toInt() and 0xFF) shl 16) or
                ((header[3].toInt() and 0xFF) shl 8) or
                (header[4].toInt() and 0xFF)

        if (ctLen < 16 || ctLen > 16 * 1024 * 1024) {
            throw IllegalArgumentException("Invalid frame length: $ctLen")
        }

        val body = readExact(inp, ctLen)
        val frame = ByteArray(5 + ctLen)
        System.arraycopy(header, 0, frame, 0, 5)
        System.arraycopy(body, 0, frame, 5, ctLen)
        return Pair(type, frame)
    }
}
