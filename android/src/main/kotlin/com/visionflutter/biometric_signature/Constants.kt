package com.visionflutter.biometric_signature

object Constants {
    const val KEYSTORE_PROVIDER = "AndroidKeyStore"

    private const val DEFAULT_BIOMETRIC_KEY_ALIAS = "biometric_key"
    private const val DEFAULT_MASTER_KEY_ALIAS = "biometric_master_key"
    private const val DEFAULT_EC_WRAPPED_FILENAME = "biometric_ec_wrapped.bin"
    private const val DEFAULT_EC_PUB_FILENAME = "biometric_ec_pub.der"

    fun biometricKeyAlias(userAlias: String?): String =
        if (userAlias == null) DEFAULT_BIOMETRIC_KEY_ALIAS
        else "biometric_key_$userAlias"

    fun masterKeyAlias(userAlias: String?): String =
        if (userAlias == null) DEFAULT_MASTER_KEY_ALIAS
        else "biometric_master_key_$userAlias"

    fun ecWrappedFilename(userAlias: String?): String =
        if (userAlias == null) DEFAULT_EC_WRAPPED_FILENAME
        else "biometric_ec_wrapped_$userAlias.bin"

    fun ecPubFilename(userAlias: String?): String =
        if (userAlias == null) DEFAULT_EC_PUB_FILENAME
        else "biometric_ec_pub_$userAlias.der"

    // Prefix used to identify plugin-managed keys in the KeyStore
    const val KEY_ALIAS_PREFIX = "biometric_key_"
    const val MASTER_KEY_ALIAS_PREFIX = "biometric_master_key_"

    const val EC_PUBKEY_SIZE = 65
    const val GCM_TAG_BITS = 128
    const val GCM_TAG_BYTES = 16
    const val AES_KEY_SIZE = 16
    const val GCM_IV_SIZE = 12
}
