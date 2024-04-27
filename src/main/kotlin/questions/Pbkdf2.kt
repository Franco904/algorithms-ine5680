package org.example.questions

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.bouncycastle.util.encoders.Hex
import java.security.Security
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

// 6 a.
private const val plainTextInput = "MAC é um hash com chave"
private const val macKeyHex = "34b6255e5fbf08d231639d210419f819"

// 6 b.
private const val password = "leopardo"
private const val salt = "53659498c0a9dcd05efe75771dadabd2"
private const val iterations = 1000

fun performPbkdf2() {
    // Add BouncyCastle security provider so we can access its algorithms
    Security.addProvider(BouncyCastleFipsProvider())

    println("plain text input: $plainTextInput")
    println("mac key: $macKeyHex\n")

    // a
    val hmacHex = generateHmacHex()
    println("hmac key: $hmacHex")

    println("\n-----\n")

    println("original key (password): $password")
    println("salt: $salt")
    println("iterations number: $iterations\n")

    // b
    val derivedKeyHex = generateDerivedKeyHex()
    println("derived key: $derivedKeyHex")
}

private fun generateHmacHex(): String {
    // Convert plain text and MAC key to bytes
    val plainTextBytes = plainTextInput.toByteArray()
    val macKeyBytes = Hex.decode(macKeyHex)

    val hmac = Mac.getInstance("HMacSHA256", "BCFIPS")
    return with(hmac) {
        val macKey = SecretKeySpec(macKeyBytes, "HMacSHA256")

        // Set up HMAC
        init(macKey)

        // Generate MAC/tag from plain text bytes
        val macValueBytes = doFinal(plainTextBytes)
        String(Hex.encode(macValueBytes), Charsets.UTF_8)
    }
}

private fun generateDerivedKeyHex(): String? {
    // Generate key spec for original key with fixed size (128 bits)
    val keySpec = PBEKeySpec(password.toCharArray(), salt.toByteArray(), iterations, 128)

    val pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", "BCFIPS")

    return try {
        // Generate derived key from key spec
        val derivedKey = pbkdf2.generateSecret(keySpec)

        // Convert key to hexcode string from bytes
        Hex.toHexString(derivedKey.encoded)
    } catch (e: Exception) {
        e.printStackTrace()
        null
    }
}
