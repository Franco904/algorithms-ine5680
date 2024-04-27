package org.example.questions

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.bouncycastle.util.encoders.Hex
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// 3
private const val keyHex = "98a99eac6fd93aed72bedfd0f0df192898a99eac6fd93aed72bedfd0f0df1928"
private const val ivHex = "ded882191c026f611757171a"
private const val encryptedTextInputHex = "899bfd986ad190de71d3d6c05ebb014bd9fee83405b098fc1e88ea1abf55647ab352d64abadcdb"

fun performChacha20() {
    // Add BouncyCastle security provider so we can access its algorithms
    Security.addProvider(BouncyCastleFipsProvider())

    // Convert secret key and IV to bytes from hexcode
    val keyBytes = Hex.decode(keyHex)
    val ivBytes = Hex.decode(ivHex)

    // Convert encrypted text input to bytes from hexcode
    val encryptedTextInputBytes = Hex.decode(encryptedTextInputHex)
    println("encrypted text input: ${Hex.toHexString(encryptedTextInputBytes)}")

    // Chacha20 (RFC 7539)
    val cipher = Cipher.getInstance("ChaCha7539", "BCFIPS")
    with(cipher) {
        val key = SecretKeySpec(keyBytes, "ChaCha7539")
        val iv = IvParameterSpec(ivBytes)

        // Set up decrypt mode
        init(Cipher.DECRYPT_MODE, key, iv)

        // Decrypt text from bytes
        val decryptedTextBytes = doFinal(encryptedTextInputBytes)
        println("decrypted text: ${String(decryptedTextBytes, Charsets.UTF_8)}")
    }
}
