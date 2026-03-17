package com.securepasswd.mgmt

import java.io.OutputStream
import java.io.OutputStreamWriter
import java.nio.charset.StandardCharsets

/**
 * Handles CSV Import/Export logic with security sanitization.
 * Compatible with the Desktop version's CSV format.
 */
object CsvManager {

    private const val HEADER = "service,username,password,totp_secret,recovery_codes"

    /**
     * Exports entries to a CSV file.
     * 
     * @param outputStream The stream to write to (from SAF).
     * @param entries List of entries to export.
     */
    fun exportToCsv(outputStream: OutputStream, entries: List<PasswordEntry>) {
        OutputStreamWriter(outputStream, StandardCharsets.UTF_8).use { writer ->
            writer.write(HEADER)
            writer.write("\n")

            for (entry in entries) {
                val row = listOf(
                    entry.service,
                    entry.username,
                    String(entry.password, StandardCharsets.UTF_8),
                    String(entry.totpSecret, StandardCharsets.UTF_8),
                    String(entry.recoveryCodes, StandardCharsets.UTF_8)
                ).joinToString(",") { field ->
                    "\"${sanitizeAndEscape(field)}\""
                }
                writer.write(row)
                writer.write("\n")
            }
        }
    }

    /**
     * Sanitizes fields against Formula Injection and escapes double quotes.
     */
    private fun sanitizeAndEscape(field: String): String {
        var sanitized = field
        // Formula Injection Protection
        if (field.startsWith('=') || field.startsWith('+') || field.startsWith('-') || field.startsWith('@')) {
            sanitized = "'$field"
        }
        // Escape double quotes by doubling them
        return sanitized.replace("\"", "\"\"")
    }

    /**
     * Basic CSV Parser for Import (Phase 5).
     * Handles quoted fields and escaped quotes.
     */
    fun parseCsv(csvContent: String): List<PasswordEntry> {
        val lines = csvContent.lines()
        if (lines.isEmpty()) return emptyList()

        // Skip header if present
        val startIndex = if (lines[0].startsWith("service", ignoreCase = true)) 1 else 0
        val entries = mutableListOf<PasswordEntry>()

        for (i in startIndex until lines.size) {
            val line = lines[i].trim()
            if (line.isEmpty()) continue

            val fields = parseCsvLine(line)
            if (fields.size >= 3) {
                entries.add(PasswordEntry(
                    id = 0, // Temporary ID for import
                    service = desanitize(fields[0]),
                    username = desanitize(fields[1]),
                    password = desanitize(fields[2]).toByteArray(StandardCharsets.UTF_8),
                    totpSecret = if (fields.size >= 4) desanitize(fields[3]).toByteArray(StandardCharsets.UTF_8) else byteArrayOf(),
                    recoveryCodes = if (fields.size >= 5) desanitize(fields[4]).toByteArray(StandardCharsets.UTF_8) else byteArrayOf()
                ))
            }
        }
        return entries
    }

    private fun desanitize(field: String): String {
        return if (field.startsWith("'") && (field.length > 1 && (field[1] == '=' || field[1] == '+' || field[1] == '-' || field[1] == '@'))) {
            field.substring(1)
        } else {
            field
        }
    }

    /**
     * Robust CSV line parser that handles quoted fields and escaped quotes.
     */
    private fun parseCsvLine(line: String): List<String> {
        val fields = mutableListOf<String>()
        var currentField = StringBuilder()
        var inQuotes = false
        var i = 0
        while (i < line.length) {
            val c = line[i]
            if (c == '\"') {
                if (inQuotes && i + 1 < line.length && line[i + 1] == '\"') {
                    // Escaped quote
                    currentField.append('\"')
                    i++
                } else {
                    inQuotes = !inQuotes
                }
            } else if (c == ',' && !inQuotes) {
                fields.add(currentField.toString())
                currentField = StringBuilder()
            } else {
                currentField.append(c)
            }
            i++
        }
        fields.add(currentField.toString())
        return fields
    }
}
