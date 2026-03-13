package com.securepasswd.mgmt

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

data class HealthStatus(
    val score: Int, // 0-100
    val label: String,
    val isReused: Boolean = false,
    val pwnedCount: Int? = null,
    val recommendations: List<String> = emptyList()
)

object HealthCheckLogic {
    fun analyzePassword(password: ByteArray, allEntries: List<PasswordEntry>, pwnedCount: Int? = null): HealthStatus {
        if (password.isEmpty()) {
            return HealthStatus(0, "Weak", recommendations = listOf("Password is empty"))
        }

        val recommendations = mutableListOf<String>()
        var score = 0

        // Length check
        if (password.size >= 16) score += 40
        else if (password.size >= 12) score += 30
        else if (password.size >= 8) score += 15
        else recommendations.add("Password is too short (min 12 chars recommended)")

        // Complexity check (using decoded chars where possible, but carefully)
        val passString = String(password, Charsets.UTF_8)
        val hasUpper = passString.any { it.isUpperCase() }
        val hasLower = passString.any { it.isLowerCase() }
        val hasDigit = passString.any { it.isDigit() }
        val hasSpecial = passString.any { !it.isLetterOrDigit() }

        if (hasUpper) score += 15
        if (hasLower) score += 15
        if (hasDigit) score += 15
        if (hasSpecial) score += 15

        if (!hasSpecial) recommendations.add("Add special characters for better security")
        if (!hasDigit) recommendations.add("Include numbers")

        // Reuse check (compare ByteArrays)
        val isReused = allEntries.any { 
            it.id != -1 && it.password.contentEquals(password) && 
            allEntries.count { e -> e.password.contentEquals(password) } > 1 
        }
        
        // We can't easily zero passString here as it's immutable, 
        // but by taking ByteArray we at least allow the caller to zero the original.

        if (isReused) {
            score -= 30
            recommendations.add("Password is reused in other entries")
        }

        val label = when {
            pwnedCount != null && pwnedCount > 0 -> "Compromised"
            score >= 85 -> "Strong"
            score >= 60 -> "Moderate"
            else -> "Weak"
        }

        if (pwnedCount != null && pwnedCount > 0) {
            recommendations.add(0, "ALERT: This password was found in $pwnedCount data breaches!")
        }

        return HealthStatus(score.coerceIn(0, 100), label, isReused, pwnedCount, recommendations)
    }

    suspend fun checkPwned(password: ByteArray): Int = withContext(Dispatchers.IO) {
        try {
            val md = MessageDigest.getInstance("SHA-1")
            val hashBytes = md.digest(password)
            val hash = hashBytes.joinToString("") { "%02X".format(it) }

            val prefix = hash.substring(0, 5)
            val suffix = hash.substring(5)

            val url = URL("https://api.pwnedpasswords.com/range/$prefix")
            val connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.setRequestProperty("User-Agent", "SecurePasswd-MGMT-Android")

            if (connection.responseCode == 200) {
                val response = connection.inputStream.bufferedReader().use { it.readText() }
                for (line in response.lines()) {
                    val parts = line.split(":")
                    if (parts.size == 2 && parts[0] == suffix) {
                        return@withContext parts[1].toInt()
                    }
                }
            }
            return@withContext 0
        } catch (e: Exception) {
            e.printStackTrace()
            return@withContext -1 // Error state
        }
    }
}
