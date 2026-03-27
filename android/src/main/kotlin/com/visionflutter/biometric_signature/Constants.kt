package com.visionflutter.biometric_signature

object Constants {
    const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    const val BIOMETRIC_KEY_ALIAS = "biometric_key"
    const val MASTER_KEY_ALIAS = "biometric_master_key"
    const val EC_WRAPPED_FILENAME = "biometric_ec_wrapped.bin"
    const val EC_PUB_FILENAME = "biometric_ec_pub.der"

    const val EC_PUBKEY_SIZE = 65
    const val GCM_TAG_BITS = 128
    const val GCM_TAG_BYTES = 16
    const val AES_KEY_SIZE = 16
    const val GCM_IV_SIZE = 12
}
