import Flutter
import UIKit
import LocalAuthentication
import Security

private enum Constants {
    static let biometricKeyAlias = "biometric_key"
    static let ecKeyAlias = "com.visionflutter.eckey".data(using: .utf8)!
    static let invalidationSettingKey = "com.visionflutter.biometric_signature.invalidation_setting"
}

// MARK: - Domain State (biometry change detection)
private enum DomainState {
    static let service = "com.visionflutter.biometric_signature.domain_state"
    private static func account() -> String { "biometric_domain_state_v1" }

    static func saveCurrent() {
        let ctx = LAContext()
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err),
              let state = ctx.evaluatedPolicyDomainState else { return }

        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account()
        ]
        let attrs: [String: Any] = [kSecValueData as String: state]
        let status = SecItemUpdate(base as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var add = base; add[kSecValueData as String] = state
            _ = SecItemAdd(add as CFDictionary, nil)
        }
    }

    static func loadSaved() -> Data? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecSuccess, let d = out as? Data { return d }
        return nil
    }

    @discardableResult
    static func deleteSaved() -> Bool {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account()
        ]
        let s = SecItemDelete(q as CFDictionary)
        return s == errSecSuccess || s == errSecItemNotFound
    }

    /// Returns true if biometry changed vs saved baseline (no UI).
    static func biometryChangedOrUnknown() -> Bool {
        let ctx = LAContext()
        var laErr: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &laErr),
        let current = ctx.evaluatedPolicyDomainState else {
            // If we can't evaluate and we *had* a baseline, be conservative.
            return loadSaved() != nil
        }
        if let saved = loadSaved() { return saved != current }
        // First run / no baseline: save now and consider valid this time.
        saveCurrent()
        return false
    }
}

// MARK: - Invalidation Setting Storage
private enum InvalidationSetting {
    static func save(_ invalidateOnEnrollment: Bool) {
        let data = invalidateOnEnrollment ? Data([1]) : Data([0])
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Constants.invalidationSettingKey,
            kSecAttrAccount as String: Constants.invalidationSettingKey
        ]
        let attrs: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(base as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var add = base
            add[kSecValueData as String] = data
            _ = SecItemAdd(add as CFDictionary, nil)
        }
    }

    static func load() -> Bool? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Constants.invalidationSettingKey,
            kSecAttrAccount as String: Constants.invalidationSettingKey,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecSuccess, let d = out as? Data, let first = d.first {
            return first == 1
        }
        return nil
    }

    @discardableResult
    static func delete() -> Bool {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Constants.invalidationSettingKey,
            kSecAttrAccount as String: Constants.invalidationSettingKey
        ]
        let s = SecItemDelete(q as CFDictionary)
        return s == errSecSuccess || s == errSecItemNotFound
    }
}

public class BiometricSignaturePlugin: NSObject, FlutterPlugin, BiometricSignatureApi {
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        let instance = BiometricSignaturePlugin()
        BiometricSignatureApiSetup.setUp(binaryMessenger: registrar.messenger(), api: instance)
    }


    // MARK: - BiometricSignatureApi Implementation

    func biometricAuthAvailable() throws -> BiometricAvailability {
        let context = LAContext()
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        
        var availableBiometrics: [BiometricType?] = []
        if canEvaluate {
             // Basic detection based on biometryType
             if #available(iOS 11.0, *) {
                 switch context.biometryType {
                 case .faceID: availableBiometrics.append(.face)
                 case .touchID: availableBiometrics.append(.fingerprint)
                 default: break
                 }
             }
        }
        
        let hasEnrolled = error?.code != LAError.biometryNotEnrolled.rawValue
        
        return BiometricAvailability(
            canAuthenticate: canEvaluate,
            hasEnrolledBiometrics: hasEnrolled,
            availableBiometrics: availableBiometrics,
            reason: error?.localizedDescription
        )
    }

    func createKeys(
        androidConfig: AndroidCreateKeysConfig?,
        iosConfig: IosCreateKeysConfig?,
        macosConfig: MacosCreateKeysConfig?,
        useDeviceCredentials: Bool?,
        signatureType: SignatureType?,
        setInvalidatedByBiometricEnrollment: Bool?,
        keyFormat: KeyFormat,
        enforceBiometric: Bool,
        promptMessage: String?,
        completion: @escaping (Result<KeyCreationResult, Error>) -> Void
    ) {
        let useDeviceCredentials = useDeviceCredentials ?? false
        let biometryCurrentSet = setInvalidatedByBiometricEnrollment ?? false
        let signatureType = signatureType ?? .rsa
        let prompt = promptMessage ?? "Authenticate to create keys"
        
        // Always delete existing keys first
        deleteExistingKeys()

        let generateBlock = {
            self.performKeyGeneration(
                useDeviceCredentials: useDeviceCredentials,
                biometryCurrentSet: biometryCurrentSet,
                signatureType: signatureType,
                keyFormat: keyFormat
            ) { result in
                completion(result)
            }
        }

        if enforceBiometric {
            let context = LAContext()
            context.localizedFallbackTitle = ""
            context.localizedReason = prompt
            
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: prompt) { success, _ in
                if success {
                    generateBlock()
                } else {
                completion(.success(KeyCreationResult(publicKey: nil, error: "Authentication failed", code: .userCanceled)))
                }
            }
        } else {
             DispatchQueue.global(qos: .userInitiated).async {
                generateBlock()
            }
        }
    }

    func createSignature(
        payload: String?,
        androidConfig: AndroidCreateSignatureConfig?,
        iosConfig: IosCreateSignatureConfig?,
        macosConfig: MacosCreateSignatureConfig?,
        signatureFormat: SignatureFormat,
        keyFormat: KeyFormat,
        promptMessage: String?,
        completion: @escaping (Result<SignatureResult, Error>) -> Void
    ) {
        guard let payload = payload, let dataToSign = payload.data(using: .utf8) else {
             completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "Invalid payload", code: .invalidInput)))
             return
        }
        
        let prompt = promptMessage ?? "Authenticate"
        let shouldMigrate = iosConfig?.shouldMigrate ?? false

        if hasRsaKey() {
             performRsaSigning(dataToSign: dataToSign, prompt: prompt, signatureFormat: signatureFormat, keyFormat: keyFormat, completion: completion)
        } else if shouldMigrate {
             migrateToSecureEnclave(prompt: prompt) { result in
                switch result {
                case .success:
                    self.performRsaSigning(dataToSign: dataToSign, prompt: prompt, signatureFormat: signatureFormat, keyFormat: keyFormat, completion: completion)
                case .failure(let error):
                    // If migration fails, returning error.
                     let msg = (error as? PigeonError)?.message ?? (error as NSError).localizedDescription
                     completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "Migration Error: \(msg)", code: .unknown)))
                }
             }
        } else {
             // Fallback to EC signing
             performEcSigning(dataToSign: dataToSign, prompt: prompt, signatureFormat: signatureFormat, keyFormat: keyFormat, completion: completion)
        }
    }

    private func migrateToSecureEnclave(prompt: String, completion: @escaping (Result<Void, Error>) -> Void) {
        // Generate EC key pair in Secure Enclave
        let ecAccessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryAny], // Defaulting to biometryAny for migration
            nil
        )

        guard let ecAccessControl = ecAccessControl else {
            completion(.failure(PigeonError(code: "authFailed", message: "Failed to create access control for EC key", details: nil)))
            return
        }

        let ecTag = Constants.ecKeyAlias
        let ecKeyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessControl as String: ecAccessControl,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: ecTag
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let ecPrivateKey = SecKeyCreateRandomKey(ecKeyAttributes as CFDictionary, &error) else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            completion(.failure(PigeonError(code: "authFailed", message: "Error generating EC key: \(msg)", details: nil)))
            return
        }

        guard let ecPublicKey = SecKeyCopyPublicKey(ecPrivateKey) else {
            completion(.failure(PigeonError(code: "authFailed", message: "Error getting EC public key", details: nil)))
            return
        }

        // Save baseline after EC key creation (migration assumes biometry-any, so no baseline needed)
        // But save the invalidation setting
        InvalidationSetting.save(false)

        let unencryptedKeyTag = Constants.biometricKeyAlias
        let unencryptedKeyTagData = unencryptedKeyTag.data(using: .utf8)!
        // Note: The legacy key was stored as kSecClassKey. The new wrapped key is kSecClassGenericPassword.
        let unencryptedKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: unencryptedKeyTagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnData as String: true
        ]

        var rsaItem: CFTypeRef?
        let status = SecItemCopyMatching(unencryptedKeyQuery as CFDictionary, &rsaItem)
        guard status == errSecSuccess else {
            completion(.failure(PigeonError(code: "authFailed", message: "RSA private key not found in Keychain", details: nil)))
            return
        }
        guard let rsaPrivateKeyData = rsaItem as? Data else {
             completion(.failure(PigeonError(code: "authFailed", message: "Failed to retrieve RSA private key data", details: nil)))
            return
        }

        let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(ecPublicKey, .encrypt, algorithm) else {
            completion(.failure(PigeonError(code: "authFailed", message: "EC encryption algorithm not supported", details: nil)))
            return
        }

        guard let encryptedRSAKeyData = SecKeyCreateEncryptedData(ecPublicKey, algorithm, rsaPrivateKeyData as CFData, &error) as Data? else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            completion(.failure(PigeonError(code: "authFailed", message: "Error encrypting RSA private key: \(msg)", details: nil)))
            return
        }

        let encryptedKeyAttributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: unencryptedKeyTag,
            kSecAttrAccount as String: unencryptedKeyTag,
            kSecValueData as String: encryptedRSAKeyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        SecItemDelete(encryptedKeyAttributes as CFDictionary) // Delete any existing item
        let storeStatus = SecItemAdd(encryptedKeyAttributes as CFDictionary, nil)
        if storeStatus != errSecSuccess {
            completion(.failure(PigeonError(code: "authFailed", message: "Error storing encrypted RSA private key in Keychain", details: nil)))
            return
        }

        // Delete the legacy unencrypted key
        SecItemDelete(unencryptedKeyQuery as CFDictionary)
        
        completion(.success(()))
    }

    func decrypt(
        payload: String?,
        payloadFormat: PayloadFormat,
        androidConfig: AndroidDecryptConfig?,
        iosConfig: IosDecryptConfig?,
        macosConfig: MacosDecryptConfig?,
        promptMessage: String?,
        completion: @escaping (Result<DecryptResult, Error>) -> Void
    ) {
        guard let payload = payload else {
             completion(.success(DecryptResult(decryptedData: nil, error: "Payload is required", code: .invalidInput)))
             return
        }
        let prompt = promptMessage ?? "Authenticate"
        let shouldMigrate = iosConfig?.shouldMigrate ?? false
        
        if hasRsaKey() {
             performRsaDecryption(payload: payload, payloadFormat: payloadFormat, prompt: prompt, completion: completion)
        } else if shouldMigrate {
             migrateToSecureEnclave(prompt: prompt) { result in
                switch result {
                case .success:
                     self.performRsaDecryption(payload: payload, payloadFormat: payloadFormat, prompt: prompt, completion: completion)
                case .failure(let error):
                     let msg = (error as? PigeonError)?.message ?? (error as NSError).localizedDescription
                     completion(.success(DecryptResult(decryptedData: nil, error: "Migration Error: \(msg)", code: .unknown)))
                }
             }
        } else {
             performEcDecryption(payload: payload, payloadFormat: payloadFormat, prompt: prompt, completion: completion)
        }
    }

    func deleteKeys() throws -> Bool {
        deleteExistingKeys()
        return true
    }

    func getKeyInfo(checkValidity: Bool, keyFormat: KeyFormat, completion: @escaping (Result<KeyInfo, Error>) -> Void) {
        // Check EC key existence
        let ecTag = Constants.ecKeyAlias
        let ecKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: ecTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var ecItem: CFTypeRef?
        let ecStatus = SecItemCopyMatching(ecKeyQuery as CFDictionary, &ecItem)
        let ecKeyExists = (ecStatus == errSecSuccess)
        let ecKey = ecItem as! SecKey?

        // Check if encrypted RSA key exists (hybrid mode)
        let encryptedKeyTag = Constants.biometricKeyAlias
        let encryptedKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: encryptedKeyTag,
            kSecAttrAccount as String: encryptedKeyTag,
            kSecReturnData as String: true,
        ]
        var rsaItem: CFTypeRef?
        let rsaStatus = SecItemCopyMatching(encryptedKeyQuery as CFDictionary, &rsaItem)
        let rsaKeyExists = (rsaStatus == errSecSuccess)

        // No keys exist
        guard ecKeyExists else {
            completion(.success(KeyInfo(exists: false)))
            return
        }

        // Determine validity
        var isValid: Bool? = nil
        if checkValidity {
            let shouldInvalidateOnEnrollment = InvalidationSetting.load() ?? true
            if shouldInvalidateOnEnrollment {
                isValid = !DomainState.biometryChangedOrUnknown()
            } else {
                isValid = true
            }
        }

        // For EC-only mode
        if ecKeyExists && !rsaKeyExists {
            guard let ecPublicKey = ecKey.flatMap({ SecKeyCopyPublicKey($0) }) else {
                completion(.success(KeyInfo(exists: true, isValid: isValid, algorithm: "EC", keySize: 256, isHybridMode: false)))
                return
            }
            
            let publicKeyStr = formatKey(ecPublicKey, format: keyFormat)
            
            completion(.success(KeyInfo(
                exists: true,
                isValid: isValid,
                algorithm: "EC",
                keySize: 256,
                isHybridMode: false,
                publicKey: publicKeyStr,
                decryptingPublicKey: nil,
                decryptingAlgorithm: nil,
                decryptingKeySize: nil
            )))
            return
        }

        // Hybrid RSA mode: Software RSA for BOTH signing and decryption
        // RSA key is wrapped with EC; we cannot retrieve RSA public key without auth
        // Note: publicKey is nil because RSA key requires biometric auth to unwrap
        completion(.success(KeyInfo(
            exists: true,
            isValid: isValid,
            algorithm: "RSA",
            keySize: 2048,
            isHybridMode: true,
            publicKey: nil, // RSA public key requires authentication to unwrap
            decryptingPublicKey: nil,
            decryptingAlgorithm: nil,
            decryptingKeySize: nil
        )))
    }

    // MARK: - Private Implementations

    private func performKeyGeneration(
        useDeviceCredentials: Bool,
        biometryCurrentSet: Bool,
        signatureType: SignatureType,
        keyFormat: KeyFormat,
        completion: @escaping (Result<KeyCreationResult, Error>) -> Void
    ) {
        // Access Control
        let flags: SecAccessControlCreateFlags = [.privateKeyUsage, useDeviceCredentials ? .userPresence : (biometryCurrentSet ? .biometryCurrentSet : .biometryAny)]
        guard let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags, nil) else {
            completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "Failed to create access control", code: .unknown)))
            return
        }
        
        // Create EC Key
        let ecTag = Constants.ecKeyAlias
        let ecAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessControl as String: accessControl,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: ecTag
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let ecPrivateKey = SecKeyCreateRandomKey(ecAttributes as CFDictionary, &error) else {
             let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown"
             completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "EC Key Gen Error: \(msg)", code: .unknown)))
             return
        }
        
        // Save metadata
        if biometryCurrentSet { DomainState.saveCurrent() }
        InvalidationSetting.save(biometryCurrentSet)
        
        guard let ecPublicKey = SecKeyCopyPublicKey(ecPrivateKey) else {
             completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "EC Pub Key Error", code: .unknown)))
             return
        }

        if signatureType == .ecdsa {
             let keyStr = formatKey(ecPublicKey, format: keyFormat)
             let data = SecKeyCopyExternalRepresentation(ecPublicKey, &error) as Data?
             let typedData = data != nil ? FlutterStandardTypedData(bytes: data!) : nil
             completion(.success(KeyCreationResult(
                 publicKey: keyStr,
                 publicKeyBytes: typedData,
                 error: nil,
                 code: .success,
                 algorithm: "EC",
                 keySize: 256,
                 decryptingPublicKey: nil,
                 decryptingAlgorithm: nil,
                 decryptingKeySize: nil,
                 isHybridMode: false
             )))
             return
        }
        
        // Check encryption support for Hybrid
        guard SecKeyIsAlgorithmSupported(ecPublicKey, .encrypt, .eciesEncryptionStandardX963SHA256AESGCM) else {
             completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "ECIES not supported", code: .unknown)))
             return
        }

        // Generate RSA Key
        let rsaAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]
        ]
        guard let rsaPrivateKey = SecKeyCreateRandomKey(rsaAttributes as CFDictionary, &error) else {
             completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "RSA Gen Error", code: .unknown)))
             return
        }
        
        // Wrap RSA Private Key
        guard let rsaPrivateData = SecKeyCopyExternalRepresentation(rsaPrivateKey, &error) as Data?,
              let encryptedRsa = SecKeyCreateEncryptedData(ecPublicKey, .eciesEncryptionStandardX963SHA256AESGCM, rsaPrivateData as CFData, &error) as Data? else {
             completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "RSA Wrapping Error", code: .unknown)))
             return
        }
        
        // Save Wrapped Key
        let tag = Constants.biometricKeyAlias
        let saveQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tag,
            kSecAttrAccount as String: tag,
            kSecValueData as String: encryptedRsa,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        SecItemAdd(saveQuery as CFDictionary, nil)
        
        guard let rsaPublicKey = SecKeyCopyPublicKey(rsaPrivateKey) else {
             completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "RSA Pub Key Error", code: .unknown)))
             return
        }
        
        let rsaData = SecKeyCopyExternalRepresentation(rsaPublicKey, &error) as Data?
        let rsaTypedData = rsaData != nil ? FlutterStandardTypedData(bytes: rsaData!) : nil
        
        let rsaKeyStr = formatKey(rsaPublicKey, format: keyFormat)
        
        completion(.success(KeyCreationResult(
            publicKey: rsaKeyStr,
            publicKeyBytes: rsaTypedData,
            error: nil,
            code: .success,
            algorithm: "RSA",
            keySize: 2048
        )))
    }
    
    private func performRsaSigning(dataToSign: Data, prompt: String, signatureFormat: SignatureFormat, keyFormat: KeyFormat, completion: @escaping (Result<SignatureResult, Error>) -> Void) {
        guard let rsaPrivateKey = unwrapRsaKey(prompt: prompt) else {
             completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "Failed to access/unwrap RSA key", code: .unknown)))
             return
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(rsaPrivateKey, .rsaSignatureMessagePKCS1v15SHA256, dataToSign as CFData, &error) as Data? else {
             let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown"
             completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "Signing Error: \(msg)", code: .unknown)))
             return
        }
        
        guard let pub = SecKeyCopyPublicKey(rsaPrivateKey) else {
             completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "Pub Key Error", code: .unknown)))
             return
        }
        
        completion(.success(SignatureResult(
            signature: formatSignature(signature, format: signatureFormat),
            signatureBytes: FlutterStandardTypedData(bytes: signature),
            publicKey: formatKey(pub, format: keyFormat),
            error: nil,
            code: .success,
            algorithm: "RSA",
            keySize: 2048
        )))
    }
    
    private func performEcSigning(dataToSign: Data, prompt: String, signatureFormat: SignatureFormat, keyFormat: KeyFormat, completion: @escaping (Result<SignatureResult, Error>) -> Void) {
        guard let ecKey = getEcPrivateKey(prompt: prompt) else {
             completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "EC Key not found or auth failed", code: .unknown)))
             return
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(ecKey, .ecdsaSignatureMessageX962SHA256, dataToSign as CFData, &error) as Data? else {
              let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown"
               completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "Signing Error: \(msg)", code: .unknown)))
              return
        }
         guard let pub = SecKeyCopyPublicKey(ecKey) else {
              completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "Pub Key Error", code: .unknown)))
             return
        }
        
        completion(.success(SignatureResult(
            signature: formatSignature(signature, format: signatureFormat),
            signatureBytes: FlutterStandardTypedData(bytes: signature),
            publicKey: formatKey(pub, format: keyFormat),
            error: nil,
            code: .success,
            algorithm: "EC",
            keySize: 256
        )))
    }
    
    private func performRsaDecryption(payload: String, payloadFormat: PayloadFormat, prompt: String, completion: @escaping (Result<DecryptResult, Error>) -> Void) {
        guard let rsaPrivateKey = unwrapRsaKey(prompt: prompt) else {
               completion(.success(DecryptResult(decryptedData: nil, error: "Failed to access/unwrap RSA key", code: .unknown)))
               return
        }
        
        var error: Unmanaged<CFError>?
        guard let encryptedData = parsePayload(payload, format: payloadFormat) else {
             completion(.success(DecryptResult(decryptedData: nil, error: "Invalid payload", code: .invalidInput)))
             return
        }
        
        guard let decrypted = SecKeyCreateDecryptedData(rsaPrivateKey, .rsaEncryptionPKCS1, encryptedData as CFData, &error) as Data?,
              let str = String(data: decrypted, encoding: .utf8) else {
             let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown"
             completion(.success(DecryptResult(decryptedData: nil, error: "Decryption Error: \(msg)", code: .unknown)))
             return
        }
        
        completion(.success(DecryptResult(decryptedData: str, error: nil, code: .success)))
    }
    
    private func performEcDecryption(payload: String, payloadFormat: PayloadFormat, prompt: String, completion: @escaping (Result<DecryptResult, Error>) -> Void) {
         guard let ecKey = getEcPrivateKey(prompt: prompt) else {
                completion(.success(DecryptResult(decryptedData: nil, error: "EC Key not found or auth failed", code: .unknown)))
               return
        }
        
        guard let encryptedData = parsePayload(payload, format: payloadFormat) else {
             completion(.success(DecryptResult(decryptedData: nil, error: "Invalid payload", code: .invalidInput)))
             return
        }
        
        var error: Unmanaged<CFError>?
        guard let decrypted = SecKeyCreateDecryptedData(ecKey, .eciesEncryptionStandardX963SHA256AESGCM, encryptedData as CFData, &error) as Data?,
              let str = String(data: decrypted, encoding: .utf8) else {
             let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown"
             completion(.success(DecryptResult(decryptedData: nil, error: "Decryption Error: \(msg)", code: .unknown)))
             return
        }
        completion(.success(DecryptResult(decryptedData: str, error: nil, code: .success)))
    }

    // MARK: - Helpers

    private func deleteExistingKeys() {
        let ecQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Constants.ecKeyAlias,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        SecItemDelete(ecQuery as CFDictionary)
        
        let rsaTag = Constants.biometricKeyAlias
        let rsaQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: rsaTag,
            kSecAttrAccount as String: rsaTag
        ]
        SecItemDelete(rsaQuery as CFDictionary)
        
        _ = DomainState.deleteSaved()
        _ = InvalidationSetting.delete()
    }
    
    private func hasRsaKey() -> Bool {
        let tag = Constants.biometricKeyAlias
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tag,
            kSecAttrAccount as String: tag,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess
    }
    
    private func getEcPrivateKey(prompt: String) -> SecKey? {
        let tag = Constants.ecKeyAlias
        let context = LAContext()
        context.localizedReason = prompt
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context
        ]
        
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess {
            return (item as! SecKey)
        }
        return nil
    }
    
    private func unwrapRsaKey(prompt: String) -> SecKey? {
        // 1. Get Wrapped Data
        let tag = Constants.biometricKeyAlias
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tag,
            kSecAttrAccount as String: tag,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let wrappedData = item as? Data else { return nil }
              
        // 2. Get EC Key (Auth logic handled by Secure Enclave)
        guard let ecKey = getEcPrivateKey(prompt: prompt) else { return nil }
        
        // 3. Unwrap
        var error: Unmanaged<CFError>?
        guard let rsaData = SecKeyCreateDecryptedData(ecKey, .eciesEncryptionStandardX963SHA256AESGCM, wrappedData as CFData, &error) as Data? else {
            return nil
        }
        
        // 4. Restore Key
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048
        ]
        return SecKeyCreateWithData(rsaData as CFData, attrs as CFDictionary, nil)
    }

    private func formatKey(_ key: SecKey, format: KeyFormat) -> String {
        guard let data = subjectPublicKeyInfo(for: key) else { return "" }
        
        switch format {
        case .base64, .raw:
            return data.base64EncodedString()
        case .pem:
            let base64 = data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
            return "-----BEGIN PUBLIC KEY-----\n\(base64)\n-----END PUBLIC KEY-----"
        case .hex:
             return data.map { String(format: "%02x", $0) }.joined()
        }
    }
    
    private func subjectPublicKeyInfo(for key: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        guard let rawData = SecKeyCopyExternalRepresentation(key, &error) as Data? else { return nil }
        
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              let keyType = attributes[kSecAttrKeyType as String] as? String else { return rawData }

        if keyType == (kSecAttrKeyTypeRSA as String) {
            // AlgorithmIdentifier: rsaEncryption, NULL
            let algorithmHeader: [UInt8] = [
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
            ]
            
            var bitString = Data()
            bitString.append(0x00) // unused bits
            bitString.append(rawData)
            let bitStringEncoded = encodeASN1Content(tag: 0x03, content: bitString)
            
            var sequenceContent = Data(algorithmHeader)
            sequenceContent.append(bitStringEncoded)
            
            return encodeASN1Content(tag: 0x30, content: sequenceContent)
            
        } else if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            // AlgorithmIdentifier: id-ecPublicKey, prime256v1
            let algorithmHeader: [UInt8] = [
                0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
            ]
            
            var bitString = Data()
            bitString.append(0x00) // unused bits
            bitString.append(rawData)
            let bitStringEncoded = encodeASN1Content(tag: 0x03, content: bitString)
            
            var sequenceContent = Data(algorithmHeader)
            sequenceContent.append(bitStringEncoded)
            return encodeASN1Content(tag: 0x30, content: sequenceContent)
        }
        
        return rawData
    }
    
    private func encodeASN1Content(tag: UInt8, content: Data) -> Data {
        var data = Data()
        data.append(tag)
        let length = content.count
        
        if length < 128 {
            data.append(UInt8(length))
        } else if length < 256 {
            data.append(0x81)
            data.append(UInt8(length))
        } else if length < 65536 {
            data.append(0x82)
            data.append(UInt8(length >> 8))
            data.append(UInt8(length & 0xFF))
        } else {
             data.append(0x83)
             data.append(UInt8(length >> 16))
             data.append(UInt8((length >> 8) & 0xFF))
             data.append(UInt8(length & 0xFF))
        }
        
        data.append(content)
        return data
    }
    
    private func formatSignature(_ data: Data, format: SignatureFormat) -> String {
        switch format {
        case .base64, .raw:
            return data.base64EncodedString()
        case .hex:
             return data.map { String(format: "%02x", $0) }.joined()
        }
    }
    
    private func parsePayload(_ payload: String, format: PayloadFormat) -> Data? {
        switch format {
        case .base64:
            return Data(base64Encoded: payload, options: .ignoreUnknownCharacters)
        case .hex:
            return parseHex(payload)
        case .raw:
            return Data(base64Encoded: payload, options: .ignoreUnknownCharacters) // Raw assumes base64 input string for transport
        }
    }
    
    private func parseHex(_ hex: String) -> Data? {
        var data = Data()
        var hexStr = hex
         if hexStr.count % 2 != 0 { hexStr = "0" + hexStr }
         for i in stride(from: 0, to: hexStr.count, by: 2) {
             let start = hexStr.index(hexStr.startIndex, offsetBy: i)
             let end = hexStr.index(start, offsetBy: 2)
             guard let byte = UInt8(hexStr[start..<end], radix: 16) else { return nil }
             data.append(byte)
         }
         return data
    }
}
