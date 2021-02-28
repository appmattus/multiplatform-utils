package fr.cryptohash

import com.appmattus.crypto.Digest
import com.appmattus.crypto.SHA1Base

class SHA1Test : SHA1Base() {
    override fun digest(): Digest<*> = SHA1()
}
