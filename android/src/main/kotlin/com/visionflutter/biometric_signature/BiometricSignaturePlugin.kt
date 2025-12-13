package com.visionflutter.biometric_signature

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import kotlinx.coroutines.*
import java.io.File
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAKeyGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * BiometricSignaturePlugin - Flutter plugin for biometric-protected cryptographic operations.
 */
class BiometricSignaturePlugin : FlutterPlugin, BiometricSignatureApi, ActivityAware {

    private companion object {
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val BIOMETRIC_KEY_ALIAS = "biometric_key"
        const val MASTER_KEY_ALIAS = "biometric_master_key"
        private const val EC_WRAPPED_FILENAME = "biometric_ec_wrapped.bin"
        private const val EC_PUB_FILENAME = "biometric_ec_pub.der"

        const val EC_PUBKEY_SIZE = 65
        const val GCM_TAG_BITS = 128
        const val GCM_TAG_BYTES = 16
        const val AES_KEY_SIZE = 16
        const val GCM_IV_SIZE = 12
    }

    private enum class KeyMode {
        RSA,
        EC_SIGN_ONLY,
        HYBRID_EC
    }

    private data class FormattedOutput(
        val value: String,
        val format: KeyFormat,
        val pemLabel: String? = null
    )

    private lateinit var appContext: Context
    private var activity: FlutterFragmentActivity? = null

    private val pluginJob = SupervisorJob()
    private val pluginScope = CoroutineScope(Dispatchers.Main.immediate + pluginJob)

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        appContext = binding.applicationContext
        BiometricSignatureApi.setUp(binding.binaryMessenger, this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        BiometricSignatureApi.setUp(binding.binaryMessenger, null)
        pluginJob.cancel()
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity as? FlutterFragmentActivity
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    override fun onDetachedFromActivityForConfigChanges() = onDetachedFromActivity()
    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) =
        onAttachedToActivity(binding)

    // ==================== BiometricSignatureApi Implementation ====================

    override fun getBiometricAvailability(): BiometricAvailability {
        val act = activity
        if (act == null) {
            return BiometricAvailability(
                canAuthenticate = false,
                hasEnrolledBiometrics = false,
                availableBiometrics = emptyList(),
                reason = "NO_ACTIVITY"
            )
        }

        val manager = BiometricManager.from(act)
        val canAuth = manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)

        val canAuthenticate = canAuth == BiometricManager.BIOMETRIC_SUCCESS
        val hasEnrolledBiometrics = canAuth != BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED &&
                canAuth != BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE &&
                canAuth != BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE

        val (types, _) = detectBiometricTypes()

        val reason = if (!canAuthenticate) biometricErrorName(canAuth) else null

        return BiometricAvailability(
            canAuthenticate = canAuthenticate,
            hasEnrolledBiometrics = hasEnrolledBiometrics,
            availableBiometrics = types,
            reason = reason
        )
    }

    override fun createKeys(
        androidConfig: AndroidCreateKeysConfig?,
        iosConfig: IosCreateKeysConfig?,
        macosConfig: MacosCreateKeysConfig?,
        useDeviceCredentials: Boolean?,
        signatureType: SignatureType?,
        setInvalidatedByBiometricEnrollment: Boolean?,
        keyFormat: KeyFormat,
        enforceBiometric: Boolean,
        promptMessage: String?,
        callback: (Result<KeyCreationResult>) -> Unit
    ) {
        val act = activity
        if (act == null) {
            callback(Result.success(KeyCreationResult(code = BiometricError.UNKNOWN, error = "Foreground activity required")))
            return
        }

        pluginScope.launch {
            try {
                val useDeviceCredentials = useDeviceCredentials ?: false
                val enableDecryption = androidConfig?.enableDecryption ?: false
                val invalidateOnEnrollment = setInvalidatedByBiometricEnrollment ?: true
                val signatureType = signatureType ?: SignatureType.RSA

                val mode = when(signatureType) {
                    SignatureType.RSA -> KeyMode.RSA
                    SignatureType.ECDSA -> if (enableDecryption) KeyMode.HYBRID_EC else KeyMode.EC_SIGN_ONLY
                }

                val prompt = promptMessage ?: "Authenticate to create keys"

                // Logic based on mode
                when (mode) {
                    KeyMode.RSA -> createRsaKeys(act, callback, useDeviceCredentials, invalidateOnEnrollment, enableDecryption, enforceBiometric, keyFormat, prompt)
                    KeyMode.EC_SIGN_ONLY -> createEcSigningKeys(act, callback, useDeviceCredentials, invalidateOnEnrollment, enforceBiometric, keyFormat, prompt)
                    KeyMode.HYBRID_EC -> createHybridEcKeys(act, callback, useDeviceCredentials, invalidateOnEnrollment, keyFormat, enforceBiometric, prompt)
                }

            } catch (e: Exception) {
                callback(Result.success(KeyCreationResult(code = mapToBiometricError(e), error = e.message)))
            }
        }
    }

    // Helper to consolidate Key creation logic return
    private suspend fun createRsaKeys(
        activity: FlutterFragmentActivity,
        callback: (Result<KeyCreationResult>) -> Unit,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        enableDecryption: Boolean,
        enforceBiometric: Boolean,
        keyFormat: KeyFormat,
        promptMessage: String
    ) {
        if (enforceBiometric) {
            checkBiometricAvailability(activity, useDeviceCredentials)
            authenticate(activity, promptMessage, null, "Cancel", useDeviceCredentials, null)
        }

        val keyPair = withContext(Dispatchers.IO) {
            deleteAllKeys()
            generateRsaKeyInKeyStore(useDeviceCredentials, invalidateOnEnrollment, enableDecryption)
        }

        val response = buildKeyResponse(keyPair.public, keyFormat)
        callback(Result.success(response))
    }

    private suspend fun createEcSigningKeys(
        activity: FlutterFragmentActivity,
        callback: (Result<KeyCreationResult>) -> Unit,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        enforceBiometric: Boolean,
        keyFormat: KeyFormat,
        promptMessage: String
    ) {
        if (enforceBiometric) {
            checkBiometricAvailability(activity, useDeviceCredentials)
            authenticate(activity, promptMessage, null, "Cancel", useDeviceCredentials, null)
        }

        val keyPair = withContext(Dispatchers.IO) {
            deleteAllKeys()
            generateEcKeyInKeyStore(useDeviceCredentials, invalidateOnEnrollment)
        }

        val response = buildKeyResponse(keyPair.public, keyFormat)
        callback(Result.success(response))
    }

    private suspend fun createHybridEcKeys(
        activity: FlutterFragmentActivity,
        callback: (Result<KeyCreationResult>) -> Unit,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        keyFormat: KeyFormat,
        enforceBiometric: Boolean,
        promptMessage: String
    ) {
        if (enforceBiometric) {
            checkBiometricAvailability(activity, useDeviceCredentials)
            authenticate(activity, promptMessage, null, "Cancel", useDeviceCredentials, null)
        }

        val signingKeyPair = withContext(Dispatchers.IO) {
            deleteAllKeys()
            val ecKeyPair = generateEcKeyInKeyStore(useDeviceCredentials, invalidateOnEnrollment)
            generateMasterKey(useDeviceCredentials, invalidateOnEnrollment)
            ecKeyPair
        }

        val cipherForWrap = withContext(Dispatchers.IO) { getCipherForEncryption() }

        checkBiometricAvailability(activity, useDeviceCredentials)
        val authResult = authenticate(
            activity,
            promptMessage,
            null,
            "Cancel",
            useDeviceCredentials,
            BiometricPrompt.CryptoObject(cipherForWrap)
        )

        val authenticatedCipher = authResult.cryptoObject?.cipher
            ?: throw SecurityException("Authentication failed - no cipher returned")

        val (wrappedBlob, publicKeyBytes) = withContext(Dispatchers.IO) {
            generateAndSealDecryptionEcKeyLocal(authenticatedCipher)
        }

        writeFileAtomic(EC_WRAPPED_FILENAME, wrappedBlob)
        writeFileAtomic(EC_PUB_FILENAME, publicKeyBytes)

        // For hybrid, we return the decryption public key as the main key
        // For hybrid, we return the Signing Key as default, and Decryption Key as optional
        val decryptingPublicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKeyBytes))

        val response = buildKeyResponse(
            publicKey = signingKeyPair.public,
            format = keyFormat,
            decryptingKey = decryptingPublicKey
        )

        callback(Result.success(response))
    }

    override fun createSignature(
        payload: String?,
        androidConfig: AndroidCreateSignatureConfig?,
        iosConfig: IosCreateSignatureConfig?,
        macosConfig: MacosCreateSignatureConfig?,
        signatureFormat: SignatureFormat,
        keyFormat: KeyFormat,
        promptMessage: String?,
        callback: (Result<SignatureResult>) -> Unit
    ) {
        val act = activity
        if (act == null) {
            callback(Result.success(SignatureResult(code = BiometricError.UNKNOWN, error = "Foreground activity required")))
            return
        }
        if (payload.isNullOrBlank()) {
            callback(Result.success(SignatureResult(code = BiometricError.UNKNOWN, error = "Payload is required")))
            return
        }

        pluginScope.launch {
            try {
                val mode = inferKeyModeFromKeystore() ?: throw SecurityException("Signing key not found")

                val allowDeviceCredentials = androidConfig?.allowDeviceCredentials ?: false

                val (signature, cryptoObject) = withContext(Dispatchers.IO) {
                    prepareSignature(mode)
                }

                checkBiometricAvailability(act, allowDeviceCredentials)

                val authResult = authenticate(
                    act,
                    promptMessage ?: "Authenticate",
                    androidConfig?.promptSubtitle,
                    androidConfig?.cancelButtonText ?: "Cancel",
                    allowDeviceCredentials,
                    cryptoObject
                )

                val signatureBytes = withContext(Dispatchers.IO) {
                    val sig = authResult.cryptoObject?.signature ?: signature
                    try {
                        sig.update(payload.toByteArray(Charsets.UTF_8))
                        sig.sign()
                    } catch (e: IllegalArgumentException) {
                        throw IllegalArgumentException("Invalid payload", e)
                    }
                }

                val publicKey = getSigningPublicKey()
                val response = buildSignatureResponse(signatureBytes, publicKey, signatureFormat, keyFormat)
                callback(Result.success(response))

            } catch (e: Exception) {
                callback(Result.success(SignatureResult(code = mapToBiometricError(e), error = e.message)))
            }
        }
    }

    override fun decrypt(
        payload: String?,
        payloadFormat: PayloadFormat,
        androidConfig: AndroidDecryptConfig?,
        iosConfig: IosDecryptConfig?,
        macosConfig: MacosDecryptConfig?,
        promptMessage: String?,
        callback: (Result<DecryptResult>) -> Unit
    ) {
        val act = activity
        if (act == null) {
            callback(Result.success(DecryptResult(code = BiometricError.UNKNOWN, error = "Foreground activity required")))
            return
        }
        if (payload.isNullOrBlank()) {
            callback(Result.success(DecryptResult(code = BiometricError.UNKNOWN, error = "Payload is required")))
            return
        }

        pluginScope.launch {
            try {
                val mode = inferKeyModeFromKeystore()
                    ?: throw SecurityException("Keys not found")

                if (mode == KeyMode.EC_SIGN_ONLY) {
                    throw SecurityException("Decryption not enabled for EC signing-only mode")
                }

                val allowDeviceCredentials = androidConfig?.allowDeviceCredentials ?: false
                val prompt = promptMessage ?: "Authenticate"
                val subtitle = androidConfig?.promptSubtitle
                val cancel = androidConfig?.cancelButtonText ?: "Cancel"

                val decryptedData = when (mode) {
                    KeyMode.RSA -> decryptRsa(act, payload, payloadFormat, prompt, subtitle, cancel, allowDeviceCredentials)
                    KeyMode.HYBRID_EC -> decryptHybridEc(act, payload, payloadFormat, prompt, subtitle, cancel, allowDeviceCredentials)
                    else -> throw SecurityException("Unsupported decryption mode")
                }

                callback(Result.success(DecryptResult(decryptedData = decryptedData, code = BiometricError.SUCCESS)))

            } catch(e: Exception) {
                callback(Result.success(DecryptResult(code = mapToBiometricError(e), error = e.message)))
            }
        }
    }

    private suspend fun decryptRsa(
        activity: FlutterFragmentActivity,
        payload: String,
        payloadFormat: PayloadFormat,
        prompt: String,
        subtitle: String?,
        cancel: String,
        allowDeviceCredentials: Boolean
    ): String {
        val cipher = withContext(Dispatchers.IO) {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            val entry = keyStore.getEntry(BIOMETRIC_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
                ?: throw IllegalStateException("RSA key not found")
            Cipher.getInstance("RSA/ECB/PKCS1Padding").apply {
                init(Cipher.DECRYPT_MODE, entry.privateKey)
            }
        }

        checkBiometricAvailability(activity, allowDeviceCredentials)

        val authResult = authenticate(
            activity, prompt, subtitle, cancel, allowDeviceCredentials,
            BiometricPrompt.CryptoObject(cipher)
        )

        val decrypted = withContext(Dispatchers.IO) {
            val authenticatedCipher = authResult.cryptoObject?.cipher
                ?: throw SecurityException("Authentication failed - no cipher returned")
            try {
                val encryptedBytes = parsePayload(payload, payloadFormat)
                authenticatedCipher.doFinal(encryptedBytes)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("Invalid Base64 payload", e)
            }
        }

        return String(decrypted, Charsets.UTF_8)
    }

    private suspend fun decryptHybridEc(
        activity: FlutterFragmentActivity,
        payload: String,
        payloadFormat: PayloadFormat,
        prompt: String,
        subtitle: String?,
        cancel: String,
        allowDeviceCredentials: Boolean
    ): String {
        val cipher = withContext(Dispatchers.IO) {
            getCipherForDecryption()
        } ?: throw SecurityException("Decryption keys not found")

        checkBiometricAvailability(activity, allowDeviceCredentials)

        val authResult = authenticate(
            activity, prompt, subtitle, cancel, allowDeviceCredentials,
            BiometricPrompt.CryptoObject(cipher)
        )

        return withContext(Dispatchers.IO) {
            val authenticatedCipher = authResult.cryptoObject?.cipher
                ?: throw SecurityException("Authentication failed - no cipher returned")
            performEciesDecryption(authenticatedCipher, payload, payloadFormat)
        }
    }

    override fun deleteKeys(): Boolean {
        deleteAllKeys()
        return true
    }

    override fun biometricKeyExists(checkValidity: Boolean, callback: (Result<Boolean>) -> Unit) {
        pluginScope.launch(Dispatchers.IO) {
            val exists = checkKeyExistsInternal(checkValidity)
            callback(Result.success(exists))
        }
    }

    private fun generateRsaKeyInKeyStore(
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        enableDecryption: Boolean
    ): KeyPair {
        val purposes = if (enableDecryption) {
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_DECRYPT
        } else {
            KeyProperties.PURPOSE_SIGN
        }

        val builder = KeyGenParameterSpec.Builder(BIOMETRIC_KEY_ALIAS, purposes)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
            .setUserAuthenticationRequired(true)

        if (enableDecryption) {
            builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
        }

        configurePerOperationAuth(builder, useDeviceCredentials)
        configureInvalidation(builder, invalidateOnEnrollment)
        tryEnableStrongBox(builder)

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER)
        kpg.initialize(builder.build())
        return kpg.generateKeyPair()
    }

    private fun generateEcKeyInKeyStore(
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean
    ): KeyPair {
        val builder = KeyGenParameterSpec.Builder(BIOMETRIC_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(true)

        configurePerOperationAuth(builder, useDeviceCredentials)
        configureInvalidation(builder, invalidateOnEnrollment)
        tryEnableStrongBox(builder)

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
        kpg.initialize(builder.build())
        return kpg.generateKeyPair()
    }

    private fun generateMasterKey(useDeviceCredentials: Boolean, invalidateOnEnrollment: Boolean) {
        val builder = KeyGenParameterSpec.Builder(
            MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)

        configurePerOperationAuth(builder, useDeviceCredentials)
        configureInvalidation(builder, invalidateOnEnrollment)

        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        keyGen.init(builder.build())
        keyGen.generateKey()
    }

    private fun getCipherForEncryption(): Cipher {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val masterKey = keyStore.getKey(MASTER_KEY_ALIAS, null) as? SecretKey
            ?: throw IllegalStateException("Master key not found")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, masterKey)
        return cipher
    }

    private fun getCipherForDecryption(): Cipher? {
        val wrapped = readFileIfExists(EC_WRAPPED_FILENAME) ?: return null
        if (wrapped.size < GCM_IV_SIZE + 1) return null

        val iv = wrapped.copyOfRange(0, GCM_IV_SIZE)
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val masterKey = keyStore.getKey(MASTER_KEY_ALIAS, null) as? SecretKey ?: return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher
    }

    private fun generateAndSealDecryptionEcKeyLocal(cipher: Cipher): Pair<ByteArray, ByteArray> {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val keyPair = kpg.generateKeyPair()

        val privateKeyBytes = keyPair.private.encoded
        val publicKeyBytes = keyPair.public.encoded

        try {
            val encrypted = cipher.doFinal(privateKeyBytes)
            val iv = cipher.iv ?: throw IllegalStateException("Cipher IV missing")
            val wrapped = ByteArray(iv.size + encrypted.size)
            System.arraycopy(iv, 0, wrapped, 0, iv.size)
            System.arraycopy(encrypted, 0, wrapped, iv.size, encrypted.size)
            return Pair(wrapped, publicKeyBytes)
        } finally {
            privateKeyBytes.fill(0)
        }
    }

    private fun prepareSignature(mode: KeyMode): Pair<Signature, BiometricPrompt.CryptoObject?> {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val entry = keyStore.getEntry(BIOMETRIC_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("Signing key not found")

        val algorithm = when (mode) {
            KeyMode.RSA -> "SHA256withRSA"
            else -> "SHA256withECDSA"
        }

        val signature = Signature.getInstance(algorithm)
        return try {
            signature.initSign(entry.privateKey)
            Pair(signature, BiometricPrompt.CryptoObject(signature))
        } catch (e: Exception) {
            Pair(signature, null)
        }
    }

    private fun getSigningPublicKey(): PublicKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val entry = keyStore.getEntry(BIOMETRIC_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("Signing key not found")
        return entry.certificate.publicKey
    }

    private fun performEciesDecryption(unwrapCipher: Cipher, payload: String, format: PayloadFormat): String {
        val wrapped = readFileIfExists(EC_WRAPPED_FILENAME)
            ?: throw IllegalStateException("Encrypted EC key not found")
        if (wrapped.size < GCM_IV_SIZE + 1) throw IllegalStateException("Malformed wrapped blob")

        val encryptedKey = wrapped.copyOfRange(GCM_IV_SIZE, wrapped.size)

        var privateKeyBytes: ByteArray? = null
        try {
            privateKeyBytes = unwrapCipher.doFinal(encryptedKey)

            val privateKey: PrivateKey = KeyFactory.getInstance("EC")
                .generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))

            val data = try {
                parsePayload(payload, format)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("Invalid payload", e)
            }
            require(data.size >= EC_PUBKEY_SIZE + GCM_TAG_BYTES) {
                "Invalid ECIES payload: too short (${data.size} bytes)"
            }

            val ephemeralKeyBytes = data.copyOfRange(0, EC_PUBKEY_SIZE)
            require(ephemeralKeyBytes[0] == 0x04.toByte()) {
                "Invalid ephemeral key: expected uncompressed (0x04)"
            }

            val ciphertextWithTag = data.copyOfRange(EC_PUBKEY_SIZE, data.size)

            val ephemeralPubKey = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(createX509ForRawEcPub(ephemeralKeyBytes)))

            val sharedSecret: ByteArray = KeyAgreement.getInstance("ECDH").run {
                init(privateKey)
                doPhase(ephemeralPubKey, true)
                generateSecret()
            }

            val derived: ByteArray = try {
                kdfX963(sharedSecret, AES_KEY_SIZE + GCM_IV_SIZE)
            } finally {
                sharedSecret.fill(0)
            }

            val aesKeyBytes = derived.copyOfRange(0, AES_KEY_SIZE)
            val gcmIv = derived.copyOfRange(AES_KEY_SIZE, AES_KEY_SIZE + GCM_IV_SIZE)
            derived.fill(0)

            try {
                val aesKey = SecretKeySpec(aesKeyBytes, "AES")
                val decrypted = Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_BITS, gcmIv))
                    doFinal(ciphertextWithTag)
                }
                return String(decrypted, Charsets.UTF_8)
            } finally {
                aesKeyBytes.fill(0)
                gcmIv.fill(0)
            }
        } finally {
            privateKeyBytes?.fill(0)
        }
    }

    // ... Helper functions
    private fun createX509ForRawEcPub(raw: ByteArray): ByteArray {
        val header = byteArrayOf(
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A.toByte(), 0x86.toByte(),
            0x48.toByte(), 0xCE.toByte(), 0x3D.toByte(), 0x02.toByte(), 0x01.toByte(),
            0x06.toByte(), 0x08.toByte(), 0x2A.toByte(), 0x86.toByte(), 0x48.toByte(),
            0xCE.toByte(), 0x3D.toByte(), 0x03.toByte(), 0x01.toByte(), 0x07.toByte(),
            0x03.toByte(), 0x42.toByte(), 0x00.toByte()
        )
        val out = ByteArray(header.size + raw.size)
        System.arraycopy(header, 0, out, 0, header.size)
        System.arraycopy(raw, 0, out, header.size, raw.size)
        return out
    }

    private fun kdfX963(secret: ByteArray, length: Int): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        val result = ByteArray(length)
        var offset = 0
        var counter = 1

        while (offset < length) {
            digest.reset()
            digest.update(secret)
            digest.update(
                byteArrayOf(
                    (counter shr 24).toByte(),
                    (counter shr 16).toByte(),
                    (counter shr 8).toByte(),
                    counter.toByte()
                )
            )
            val hash = digest.digest()
            val toCopy = minOf(hash.size, length - offset)
            System.arraycopy(hash, 0, result, offset, toCopy)
            offset += toCopy
            counter++
        }
        return result
    }

    private fun deleteAllKeys() {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        runCatching { keyStore.deleteEntry(BIOMETRIC_KEY_ALIAS) }
        runCatching { keyStore.deleteEntry(MASTER_KEY_ALIAS) }

        listOf(EC_WRAPPED_FILENAME, EC_PUB_FILENAME).forEach { fileName ->
            val file = File(appContext.filesDir, fileName)
            if (file.exists()) {
                runCatching { file.writeBytes(ByteArray(file.length().toInt())) }
                file.delete()
            }
        }
    }

    private fun biometricErrorName(code: Int) = when (code) {
        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "BIOMETRIC_ERROR_NO_HARDWARE"
        BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "BIOMETRIC_ERROR_HW_UNAVAILABLE"
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "BIOMETRIC_ERROR_NONE_ENROLLED"
        BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED"
        BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> "BIOMETRIC_ERROR_UNSUPPORTED"
        BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> "BIOMETRIC_STATUS_UNKNOWN"
        else -> "UNKNOWN_ERROR"
    }

    private fun checkKeyExistsInternal(checkValidity: Boolean): Boolean {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (!keyStore.containsAlias(BIOMETRIC_KEY_ALIAS)) return false
        if (!checkValidity) return true

        return runCatching {
            val entry = keyStore.getEntry(BIOMETRIC_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
            entry != null
        }.getOrDefault(false)
    }

    private fun inferKeyModeFromKeystore(): KeyMode? {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (!keyStore.containsAlias(BIOMETRIC_KEY_ALIAS)) return null
        val entry = keyStore.getEntry(BIOMETRIC_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry ?: return null
        val pub = entry.certificate.publicKey
        return when (pub) {
            is RSAPublicKey -> KeyMode.RSA
            is ECPublicKey -> {
                val wrappedExists = File(appContext.filesDir, EC_WRAPPED_FILENAME).exists()
                if (wrappedExists) KeyMode.HYBRID_EC else KeyMode.EC_SIGN_ONLY
            }
            else -> null
        }
    }

    private suspend fun checkBiometricAvailability(
        activity: FragmentActivity,
        allowDeviceCredentials: Boolean
    ) {
        val authenticators = getAuthenticators(allowDeviceCredentials)
        val canAuth = BiometricManager.from(activity).canAuthenticate(authenticators)
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            throw SecurityException("Biometric not available (code: ${biometricErrorName(canAuth)})")
        }
    }

    private suspend fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String?,
        cancelText: String,
        allowDeviceCredentials: Boolean,
        cryptoObject: BiometricPrompt.CryptoObject?
    ): BiometricPrompt.AuthenticationResult = suspendCancellableCoroutine { cont ->
        val authenticators = getAuthenticators(allowDeviceCredentials)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (cont.isActive) cont.resume(result)
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (cont.isActive) {
                    // Map error codes to standard exceptions if needed, or pass raw
                    cont.resumeWithException(SecurityException("$errString", Throwable(errorCode.toString())))
                }
            }
            override fun onAuthenticationFailed() { /* Retry */ }
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setAllowedAuthenticators(authenticators)
            .apply {
                if (!subtitle.isNullOrBlank()) setSubtitle(subtitle)
                if (!(allowDeviceCredentials && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)) {
                    setNegativeButtonText(cancelText)
                }
            }
            .build()

        runCatching {
            activity.setTheme(androidx.appcompat.R.style.Theme_AppCompat_Light_DarkActionBar)
            val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
            if (cryptoObject != null) prompt.authenticate(promptInfo, cryptoObject)
            else prompt.authenticate(promptInfo)
        }.onFailure { e -> if (cont.isActive) cont.resumeWithException(e) }
    }

    private fun getAuthenticators(allowDeviceCredentials: Boolean): Int {
        return if (allowDeviceCredentials && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        }
    }

    private fun configurePerOperationAuth(builder: KeyGenParameterSpec.Builder, useDeviceCredentials: Boolean) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val authType = if (useDeviceCredentials) {
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            } else {
                KeyProperties.AUTH_BIOMETRIC_STRONG
            }
            builder.setUserAuthenticationParameters(0, authType)
        } else {
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
    }

    private fun configureInvalidation(builder: KeyGenParameterSpec.Builder, invalidateOnEnrollment: Boolean) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && invalidateOnEnrollment) {
            builder.setInvalidatedByBiometricEnrollment(true)
        }
    }

    private fun tryEnableStrongBox(builder: KeyGenParameterSpec.Builder) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            try { builder.setIsStrongBoxBacked(true) } catch (_: Throwable) {}
        }
    }

    private fun buildKeyResponse(
        publicKey: PublicKey,
        format: KeyFormat,
        decryptingKey: PublicKey? = null
    ): KeyCreationResult {
        val formatted = formatOutput(publicKey.encoded, format)
        val keySize = (publicKey as? java.security.interfaces.RSAKey)?.modulus?.bitLength()
            ?: (publicKey as? java.security.interfaces.ECKey)?.params?.order?.bitLength()

        var decryptingFormatted: FormattedOutput? = null
        var decryptingAlgorithm: String? = null
        var decryptingKeySize: Long? = null

        if (decryptingKey != null) {
            decryptingFormatted = formatOutput(decryptingKey.encoded, format)
            decryptingAlgorithm = decryptingKey.algorithm
            decryptingKeySize = ((decryptingKey as? java.security.interfaces.RSAKey)?.modulus?.bitLength()
                ?: (decryptingKey as? java.security.interfaces.ECKey)?.params?.order?.bitLength())?.toLong()
        }

        return KeyCreationResult(
            publicKey = formatted.value,
            publicKeyBytes = publicKey.encoded,
            code = BiometricError.SUCCESS,
            algorithm = publicKey.algorithm,
            keySize = keySize?.toLong(),
            decryptingPublicKey = decryptingFormatted?.value,
            decryptingAlgorithm = decryptingAlgorithm,
            decryptingKeySize = decryptingKeySize,
            isHybridMode = decryptingKey != null
        )
    }

    private fun buildSignatureResponse(
        signatureBytes: ByteArray,
        publicKey: PublicKey,
        format: SignatureFormat,
        keyFormat: KeyFormat
    ): SignatureResult {

        // Format signature explicitly based on SignatureFormat
        val sigString = when(format) {
            SignatureFormat.BASE64, SignatureFormat.RAW -> Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
            SignatureFormat.HEX -> bytesToHex(signatureBytes)
        }

        val pubFormatted = formatOutput(publicKey.encoded, keyFormat)
        val keySize = (publicKey as? java.security.interfaces.RSAKey)?.modulus?.bitLength()
            ?: (publicKey as? java.security.interfaces.ECKey)?.params?.order?.bitLength()

        return SignatureResult(
            signature = sigString,
            signatureBytes = signatureBytes,
            publicKey = pubFormatted.value,
            code = BiometricError.SUCCESS,
            algorithm = publicKey.algorithm,
            keySize = keySize?.toLong()
        )
    }

    private fun formatOutput(bytes: ByteArray, format: KeyFormat, label: String = "PUBLIC KEY"): FormattedOutput =
        when (format) {
            KeyFormat.BASE64 -> FormattedOutput(Base64.encodeToString(bytes, Base64.NO_WRAP), format)
            KeyFormat.PEM -> FormattedOutput(
                "-----BEGIN $label-----\n${Base64.encodeToString(bytes, Base64.NO_WRAP).chunked(64).joinToString("\n")}\n-----END $label-----",
                format,
                label
            )
            KeyFormat.HEX -> FormattedOutput(bytesToHex(bytes), format)
            KeyFormat.RAW -> FormattedOutput(Base64.encodeToString(bytes, Base64.NO_WRAP), format)
        }

    private fun parsePayload(payload: String, format: PayloadFormat): ByteArray {
        return when (format) {
            PayloadFormat.BASE64, PayloadFormat.RAW -> Base64.decode(payload, Base64.NO_WRAP)
            PayloadFormat.HEX -> hexToBytes(payload)
        }
    }

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun hexToBytes(hex: String): ByteArray {
        val cleanHex = if (hex.length % 2 != 0) "0$hex" else hex
        return cleanHex.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }

    private fun detectBiometricTypes(): Pair<List<BiometricType>, String?> {
        var identifiedFingerprint = false
        val pm = appContext.packageManager

        if (pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
            val fm = appContext.getSystemService(FingerprintManager::class.java)
            val enrolled = try {
                fm?.hasEnrolledFingerprints() == true
            } catch (_: SecurityException) {
                true
            }
            identifiedFingerprint = fm?.isHardwareDetected == true && enrolled
        }

        val otherString = listOf("face", "iris", ",")
        val biometricManager = BiometricManager.from(activity!!)

        // Use reflection to access getStrings(int authenticators)
        var buttonLabel: String? = null
        try {
            val getStringsMethod = BiometricManager::class.java.getMethod("getStrings", Int::class.javaPrimitiveType)
            val strings = getStringsMethod.invoke(biometricManager, BiometricManager.Authenticators.BIOMETRIC_STRONG)
            if (strings != null) {
                val getButtonLabelMethod = strings.javaClass.getMethod("getButtonLabel")
                buttonLabel = getButtonLabelMethod.invoke(strings) as? String
            }
        } catch (e: Exception) {
            // Reflection failed or method not found, ignore
        }

        val otherBiometrics = otherString.filter {
            buttonLabel?.contains(it, ignoreCase = true) == true
        }

        val resultString = if (identifiedFingerprint) {
            if (otherBiometrics.isEmpty()) "fingerprint" else "biometric"
        } else {
            if (otherBiometrics.size == 1 && otherBiometrics[0] != ",") otherBiometrics[0] else "biometric"
        }

        // Map string to List<BiometricType>
        val types = mutableListOf<BiometricType>()

        if (resultString == "fingerprint") {
            types.add(BiometricType.FINGERPRINT)
        } else if (resultString == "face") {
            types.add(BiometricType.FACE)
        } else if (resultString == "iris") {
            types.add(BiometricType.IRIS)
        } else if (resultString == "biometric") {
            // Fallback or multiple
            types.add(BiometricType.MULTIPLE)
        }

        return Pair(types, null)
    }

    private fun mapToBiometricError(e: Throwable): BiometricError {
        // Map exceptions to BiometricError
        val msg = e.message ?: ""
        return when {
            msg.contains("BIOMETRIC_ERROR_NONE_ENROLLED") -> BiometricError.NOT_ENROLLED
            msg.contains("BIOMETRIC_ERROR_NO_HARDWARE") -> BiometricError.NOT_AVAILABLE
            msg.contains("BIOMETRIC_ERROR_HW_UNAVAILABLE") -> BiometricError.NOT_AVAILABLE
            // User canceled
            // e.cause might contain code 
            e.cause?.message == "10" -> BiometricError.USER_CANCELED // 10 is USER_CANCELED usually
            e.cause?.message == "13" -> BiometricError.USER_CANCELED // Negative button

            // Map simple Cancellation
            e is CancellationException -> BiometricError.USER_CANCELED

            e is IllegalArgumentException && (e.message?.contains("Base64") == true || e.message?.contains("payload") == true) -> BiometricError.INVALID_INPUT

            else -> BiometricError.UNKNOWN
        }
    }

    private fun writeFileAtomic(fileName: String, data: ByteArray) {
        File(appContext.filesDir, fileName).outputStream().use { it.write(data) }
    }
    private fun readFileIfExists(fileName: String): ByteArray? {
        val file = File(appContext.filesDir, fileName)
        return if (!file.exists()) null else file.readBytes()
    }
}
