package org.example.questions

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.bouncycastle.util.encoders.Hex
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// 5
private const val keyHex = "c66fb0c759979ff3cfcc331706db7c08"
private const val ivHex = "a7cd1202648faac8fc99806b0269811c"
private const val encryptedTextInputHex = "4dad2f5f830e8521c0a1b4e3da7a877703e3ec7573e2cdd27da4da5edfda5b74df712d0c61900efd54"

fun performAesCtrNoPadding() {
    // Add BouncyCastle security provider so we can access its algorithms
    Security.addProvider(BouncyCastleFipsProvider())

    // Convert secret Key input and IV to bytes from hexcode
    val keyBytes = Hex.decode(keyHex)
    val ivBytes = Hex.decode(ivHex)

    // Convert encrypted text input to bytes from hexcode
    val encryptedTextInputBytes = Hex.decode(encryptedTextInputHex)
    println("encrypted text input: ${Hex.toHexString(encryptedTextInputBytes)}")

    val cipher = Cipher.getInstance("AES/CTR/NoPadding", "BCFIPS")
    with(cipher) {
        val key = SecretKeySpec(keyBytes, "AES")
        val iv = IvParameterSpec(ivBytes)

        // Set up decrypt mode
        init(Cipher.DECRYPT_MODE, key, iv)

        // Decrypt text from bytes
        val decryptedTextBytes = doFinal(encryptedTextInputBytes)
        println("decrypted text: ${String(decryptedTextBytes, Charsets.UTF_8)}")
    }
}
