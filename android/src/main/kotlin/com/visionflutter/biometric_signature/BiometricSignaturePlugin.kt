package com.visionflutter.biometric_signature

import android.content.Context
import androidx.biometric.BiometricPrompt
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import kotlinx.coroutines.*
import java.security.*
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

class BiometricSignaturePlugin : FlutterPlugin, BiometricSignatureApi, ActivityAware {

    private lateinit var appContext: Context
    @Volatile
    private var activity: FlutterFragmentActivity? = null

    private val pluginJob = SupervisorJob()
    private val pluginScope = CoroutineScope(Dispatchers.Main.immediate + pluginJob)

    private lateinit var fileIOHelper: FileIOHelper
    private lateinit var keyManager: KeyManager
    private lateinit var cryptoOperations: CryptoOperations
    private lateinit var biometricPromptHelper: BiometricPromptHelper

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        appContext = binding.applicationContext
        
        fileIOHelper = FileIOHelper(appContext)
        keyManager = KeyManager(appContext, fileIOHelper)
        cryptoOperations = CryptoOperations(fileIOHelper)
        biometricPromptHelper = BiometricPromptHelper(appContext)

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

    override fun biometricAuthAvailable(callback: (Result<BiometricAvailability>) -> Unit) {
        val act = activity
        if (act == null) {
            callback(
                Result.success(
                    BiometricAvailability(
                        canAuthenticate = false,
                        hasEnrolledBiometrics = false,
                        availableBiometrics = emptyList(),
                        reason = "NO_ACTIVITY"
                    )
                )
            )
            return
        }

        val manager = androidx.biometric.BiometricManager.from(act)
        val canAuth = manager.canAuthenticate(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)

        val canAuthenticate = canAuth == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
        val hasEnrolledBiometrics = canAuth != androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED &&
                canAuth != androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE &&
                canAuth != androidx.biometric.BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE

        val biometricTypes = biometricPromptHelper.detectBiometricTypes()
        val reason = if (!canAuthenticate) ErrorMapper.biometricErrorName(canAuth) else null

        callback(
            Result.success(
                BiometricAvailability(
                    canAuthenticate = canAuthenticate,
                    hasEnrolledBiometrics = hasEnrolledBiometrics,
                    availableBiometrics = biometricTypes,
                    reason = reason
                )
            )
        )
    }

    override fun createKeys(
        config: CreateKeysConfig?,
        keyFormat: KeyFormat,
        promptMessage: String?,
        callback: (Result<KeyCreationResult>) -> Unit
    ) {
        val act = activity
        if (act == null) {
            callback(
                Result.success(
                    KeyCreationResult(
                        code = BiometricError.UNKNOWN,
                        error = "Foreground activity required"
                    )
                )
            )
            return
        }

        pluginScope.launch {
            try {
                val useDeviceCredentials = config?.useDeviceCredentials ?: false
                val enableDecryption = config?.enableDecryption ?: false
                val invalidateOnEnrollment = config?.setInvalidatedByBiometricEnrollment ?: true
                val signatureType = config?.signatureType ?: SignatureType.RSA
                val enforceBiometric = config?.enforceBiometric ?: false

                val mode = when (signatureType) {
                    SignatureType.RSA -> KeyMode.RSA
                    SignatureType.ECDSA -> if (enableDecryption) KeyMode.HYBRID_EC else KeyMode.EC_SIGN_ONLY
                }

                val prompt = promptMessage ?: "Authenticate to create keys"

                when (mode) {
                    KeyMode.RSA -> createRsaKeys(act, callback, useDeviceCredentials, invalidateOnEnrollment, enableDecryption, enforceBiometric, keyFormat, prompt)
                    KeyMode.EC_SIGN_ONLY -> createEcSigningKeys(act, callback, useDeviceCredentials, invalidateOnEnrollment, enforceBiometric, keyFormat, prompt)
                    KeyMode.HYBRID_EC -> createHybridEcKeys(act, callback, useDeviceCredentials, invalidateOnEnrollment, keyFormat, enforceBiometric, prompt)
                }
            } catch (e: Exception) {
                callback(
                    Result.success(
                        KeyCreationResult(
                            code = ErrorMapper.mapToBiometricError(e),
                            error = ErrorMapper.safeErrorMessage(e)
                        )
                    )
                )
            }
        }
    }

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
            biometricPromptHelper.checkBiometricAvailability(activity, useDeviceCredentials)
            biometricPromptHelper.authenticate(activity, promptMessage, null, null, "Cancel", useDeviceCredentials, null)
        }

        val keyPair = withContext(Dispatchers.IO) {
            keyManager.deleteAllKeys()
            keyManager.generateRsaKeyInKeyStore(useDeviceCredentials, invalidateOnEnrollment, enableDecryption)
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
            biometricPromptHelper.checkBiometricAvailability(activity, useDeviceCredentials)
            biometricPromptHelper.authenticate(activity, promptMessage, null, null, "Cancel", useDeviceCredentials, null)
        }

        val keyPair = withContext(Dispatchers.IO) {
            keyManager.deleteAllKeys()
            keyManager.generateEcKeyInKeyStore(useDeviceCredentials, invalidateOnEnrollment)
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
            biometricPromptHelper.checkBiometricAvailability(activity, useDeviceCredentials)
            biometricPromptHelper.authenticate(activity, promptMessage, null, null, "Cancel", useDeviceCredentials, null)
        }

        val signingKeyPair = withContext(Dispatchers.IO) {
            keyManager.deleteAllKeys()
            val ecKeyPair = keyManager.generateEcKeyInKeyStore(useDeviceCredentials, invalidateOnEnrollment)
            keyManager.generateMasterKey(useDeviceCredentials, invalidateOnEnrollment)
            ecKeyPair
        }

        val cipherForWrap = withContext(Dispatchers.IO) { cryptoOperations.getCipherForEncryption() }

        biometricPromptHelper.checkBiometricAvailability(activity, useDeviceCredentials)
        val authResult = biometricPromptHelper.authenticate(
            activity, promptMessage, null, null, "Cancel", useDeviceCredentials, BiometricPrompt.CryptoObject(cipherForWrap)
        )

        val authenticatedCipher = authResult.cryptoObject?.cipher
            ?: throw SecurityException("Authentication failed - no cipher returned")

        val (wrappedBlob, publicKeyBytes) = withContext(Dispatchers.IO) {
            cryptoOperations.generateAndSealDecryptionEcKeyLocal(authenticatedCipher)
        }

        fileIOHelper.writeFileAtomic(Constants.EC_WRAPPED_FILENAME, wrappedBlob)
        fileIOHelper.writeFileAtomic(Constants.EC_PUB_FILENAME, publicKeyBytes)

        val decryptingPublicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKeyBytes))

        val response = buildKeyResponse(
            publicKey = signingKeyPair.public,
            format = keyFormat,
            decryptingKey = decryptingPublicKey
        )

        callback(Result.success(response))
    }

    override fun createSignature(
        payload: String,
        config: CreateSignatureConfig?,
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
        if (payload.isBlank()) {
            callback(Result.success(SignatureResult(code = BiometricError.INVALID_INPUT, error = "Payload is required")))
            return
        }

        pluginScope.launch {
            try {
                val mode = keyManager.inferKeyModeFromKeystore() ?: throw SecurityException("Signing key not found")
                val allowDeviceCredentials = config?.allowDeviceCredentials ?: false

                val (signature, cryptoObject) = withContext(Dispatchers.IO) {
                    cryptoOperations.prepareSignature(mode)
                }

                biometricPromptHelper.checkBiometricAvailability(act, allowDeviceCredentials)

                val authResult = biometricPromptHelper.authenticate(
                    act, promptMessage ?: "Authenticate", config?.promptSubtitle, null, config?.cancelButtonText ?: "Cancel", allowDeviceCredentials, cryptoObject
                )

                val signatureBytes = withContext(Dispatchers.IO) {
                    val sig = authResult.cryptoObject?.signature ?: throw SecurityException("Biometric authentication did not return an authenticated signature")
                    try {
                        sig.update(payload.toByteArray(Charsets.UTF_8))
                        sig.sign()
                    } catch (e: IllegalArgumentException) {
                        throw IllegalArgumentException("Invalid payload", e)
                    }
                }

                val publicKey = cryptoOperations.getSigningPublicKey()
                val response = buildSignatureResponse(signatureBytes, publicKey, signatureFormat, keyFormat)
                callback(Result.success(response))

            } catch (e: Exception) {
                callback(Result.success(SignatureResult(code = ErrorMapper.mapToBiometricError(e), error = ErrorMapper.safeErrorMessage(e))))
            }
        }
    }

    override fun decrypt(
        payload: String,
        payloadFormat: PayloadFormat,
        config: DecryptConfig?,
        promptMessage: String?,
        callback: (Result<DecryptResult>) -> Unit
    ) {
        val act = activity
        if (act == null) {
            callback(Result.success(DecryptResult(code = BiometricError.UNKNOWN, error = "Foreground activity required")))
            return
        }
        if (payload.isBlank()) {
            callback(Result.success(DecryptResult(code = BiometricError.INVALID_INPUT, error = "Payload is required")))
            return
        }

        pluginScope.launch {
            try {
                val mode = keyManager.inferKeyModeFromKeystore() ?: throw SecurityException("Keys not found")

                if (mode == KeyMode.EC_SIGN_ONLY) {
                    throw SecurityException("Decryption not enabled for EC signing-only mode")
                }

                val allowDeviceCredentials = config?.allowDeviceCredentials ?: false
                val prompt = promptMessage ?: "Authenticate"
                val subtitle = config?.promptSubtitle
                val cancel = config?.cancelButtonText ?: "Cancel"

                val decryptedData = when (mode) {
                    KeyMode.RSA -> decryptRsa(act, payload, payloadFormat, prompt, subtitle, cancel, allowDeviceCredentials)
                    KeyMode.HYBRID_EC -> decryptHybridEc(act, payload, payloadFormat, prompt, subtitle, cancel, allowDeviceCredentials)
                    else -> throw SecurityException("Unsupported decryption mode")
                }

                callback(Result.success(DecryptResult(decryptedData = decryptedData, code = BiometricError.SUCCESS)))

            } catch (e: Exception) {
                callback(Result.success(DecryptResult(code = ErrorMapper.mapToBiometricError(e), error = ErrorMapper.safeErrorMessage(e))))
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
            val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
            val entry = keyStore.getEntry(Constants.BIOMETRIC_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
                ?: throw IllegalStateException("RSA key not found")
            try {
                Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding").apply {
                    init(Cipher.DECRYPT_MODE, entry.privateKey)
                }
            } catch (e: InvalidKeyException) {
                Cipher.getInstance("RSA/ECB/PKCS1Padding").apply {
                    init(Cipher.DECRYPT_MODE, entry.privateKey)
                }
            }
        }

        biometricPromptHelper.checkBiometricAvailability(activity, allowDeviceCredentials)

        val authResult = biometricPromptHelper.authenticate(
            activity, prompt, subtitle, null, cancel, allowDeviceCredentials, BiometricPrompt.CryptoObject(cipher)
        )

        val decrypted = withContext(Dispatchers.IO) {
            val authenticatedCipher = authResult.cryptoObject?.cipher
                ?: throw SecurityException("Authentication failed - no cipher returned")
            try {
                val encryptedBytes = FormatUtils.parsePayload(payload, payloadFormat)
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
        val cipher = withContext(Dispatchers.IO) { cryptoOperations.getCipherForDecryption() }
            ?: throw SecurityException("Decryption keys not found")

        biometricPromptHelper.checkBiometricAvailability(activity, allowDeviceCredentials)

        val authResult = biometricPromptHelper.authenticate(
            activity, prompt, subtitle, null, cancel, allowDeviceCredentials, BiometricPrompt.CryptoObject(cipher)
        )

        return withContext(Dispatchers.IO) {
            val authenticatedCipher = authResult.cryptoObject?.cipher ?: throw SecurityException("Authentication failed - no cipher returned")
            cryptoOperations.performEciesDecryption(authenticatedCipher, payload, payloadFormat)
        }
    }

    override fun deleteKeys(callback: (Result<Boolean>) -> Unit) {
        pluginScope.launch {
            withContext(Dispatchers.IO) { keyManager.deleteAllKeys() }
            callback(Result.success(true))
        }
    }

    override fun getKeyInfo(
        checkValidity: Boolean,
        keyFormat: KeyFormat,
        callback: (Result<KeyInfo>) -> Unit
    ) {
        pluginScope.launch {
            try {
                val keyInfo = withContext(Dispatchers.IO) {
                    val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
                    if (!keyStore.containsAlias(Constants.BIOMETRIC_KEY_ALIAS)) {
                        return@withContext KeyInfo(exists = false)
                    }

                    val entry = keyStore.getEntry(Constants.BIOMETRIC_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
                        ?: return@withContext KeyInfo(exists = false)

                    val publicKey = entry.certificate.publicKey
                    val mode = keyManager.inferKeyModeFromKeystore()

                    val isValid = if (checkValidity) {
                        runCatching {
                            val algorithm = when (mode) {
                                KeyMode.RSA -> "SHA256withRSA"
                                else -> "SHA256withECDSA"
                            }
                            val signature = java.security.Signature.getInstance(algorithm)
                            signature.initSign(entry.privateKey)
                            true
                        }.getOrDefault(false)
                    } else {
                        null
                    }

                    val algorithm = publicKey.algorithm
                    val keySize = (publicKey as? java.security.interfaces.RSAKey)?.modulus?.bitLength()?.toLong()
                        ?: (publicKey as? java.security.interfaces.ECKey)?.params?.order?.bitLength()?.toLong()

                    val formattedPublicKey = FormatUtils.formatOutput(publicKey.encoded, keyFormat)

                    val isHybridMode = mode == KeyMode.HYBRID_EC
                    val decryptingInfo = if (isHybridMode) {
                        val pubBytes = fileIOHelper.readFileIfExists(Constants.EC_PUB_FILENAME)
                        if (pubBytes != null) {
                            val decryptKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(pubBytes))
                            Triple(FormatUtils.formatOutput(decryptKey.encoded, keyFormat).value, "EC", 256L)
                        } else null
                    } else null

                    KeyInfo(
                        exists = true,
                        isValid = isValid,
                        algorithm = algorithm,
                        keySize = keySize,
                        isHybridMode = isHybridMode,
                        publicKey = formattedPublicKey.value,
                        decryptingPublicKey = decryptingInfo?.first,
                        decryptingAlgorithm = decryptingInfo?.second,
                        decryptingKeySize = decryptingInfo?.third
                    )
                }
                callback(Result.success(keyInfo))
            } catch (e: Exception) {
                callback(Result.success(KeyInfo(exists = false)))
            }
        }
    }

    override fun simplePrompt(
        promptMessage: String,
        config: SimplePromptConfig?,
        callback: (Result<SimplePromptResult>) -> Unit
    ) {
        val act = activity
        if (act == null) {
            callback(Result.success(SimplePromptResult(success = false, error = "Foreground activity required", code = BiometricError.PROMPT_ERROR)))
            return
        }

        pluginScope.launch {
            try {
                val allowDeviceCredentials = config?.allowDeviceCredentials ?: false
                val biometricStrength = config?.biometricStrength ?: BiometricStrength.STRONG

                val authenticators = biometricPromptHelper.getAuthenticators(allowDeviceCredentials, biometricStrength)
                val canAuth = androidx.biometric.BiometricManager.from(act).canAuthenticate(authenticators)

                if (canAuth != androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS) {
                    val (errorCode, errorMsg) = ErrorMapper.mapBiometricManagerError(canAuth, biometricStrength)
                    callback(Result.success(SimplePromptResult(success = false, error = errorMsg, code = errorCode)))
                    return@launch
                }

                val cancelText = config?.cancelButtonText ?: "Cancel"
                val authResult = biometricPromptHelper.authenticate(
                    act, promptMessage, config?.subtitle, config?.description, cancelText, allowDeviceCredentials, null
                )

                callback(Result.success(SimplePromptResult(success = true, code = BiometricError.SUCCESS)))

            } catch (e: Exception) {
                val errorCode = ErrorMapper.mapToBiometricError(e)
                callback(Result.success(SimplePromptResult(success = false, error = ErrorMapper.safeErrorMessage(e), code = errorCode)))
            }
        }
    }

    private fun buildKeyResponse(publicKey: PublicKey, format: KeyFormat, decryptingKey: PublicKey? = null): KeyCreationResult {
        val formatted = FormatUtils.formatOutput(publicKey.encoded, format)
        val keySize = (publicKey as? java.security.interfaces.RSAKey)?.modulus?.bitLength()
            ?: (publicKey as? java.security.interfaces.ECKey)?.params?.order?.bitLength()

        var decryptingFormatted: FormatUtils.FormattedOutput? = null
        var decryptingAlgorithm: String? = null
        var decryptingKeySize: Long? = null

        if (decryptingKey != null) {
            decryptingFormatted = FormatUtils.formatOutput(decryptingKey.encoded, format)
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

    private fun buildSignatureResponse(signatureBytes: ByteArray, publicKey: PublicKey, format: SignatureFormat, keyFormat: KeyFormat): SignatureResult {
        val sigString = when (format) {
            SignatureFormat.BASE64, SignatureFormat.RAW -> android.util.Base64.encodeToString(signatureBytes, android.util.Base64.NO_WRAP)
            SignatureFormat.HEX -> FormatUtils.bytesToHex(signatureBytes)
        }

        val pubFormatted = FormatUtils.formatOutput(publicKey.encoded, keyFormat)
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
}
