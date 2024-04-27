package org.example

import org.example.questions.performAesCtrNoPadding
import org.example.questions.performChacha20
import org.example.questions.performPbkdf2

fun main() {
    // 3
    performChacha20()

    // 5
    performAesCtrNoPadding()

    // 6
    performPbkdf2()
}
