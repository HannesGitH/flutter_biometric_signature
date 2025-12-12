import Cocoa
import FlutterMacOS
import LocalAuthentication
import Security

private enum Constants {
    static let biometricKeyAlias = "biometric_key"
    static let ecKeyAlias = "com.visionflutter.eckey".data(using: .utf8)!
    static let invalidationSettingKey = "com.visionflutter.biometric_signature.invalidation_setting"
}

// MARK: - Domain State & Invalidation Helpers (Shared Logic)
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
}

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
        BiometricSignatureApiSetup.setUp(binaryMessenger: registrar.messenger, api: instance)
    }

    // MARK: - BiometricSignatureApi Implementation

    func getBiometricAvailability() throws -> BiometricAvailability {
        let context = LAContext()
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        
        var availableBiometrics: [BiometricType?] = []
        if canEvaluate {
             // macOS only supports TouchID currently
             if #available(macOS 10.12.2, *) {
                 if context.biometryType == .touchID {
                     availableBiometrics.append(.fingerprint)
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
        androidConfig: AndroidConfig?,
        iosConfig: IosConfig?,
        macosConfig: MacosConfig?,
        keyFormat: KeyFormat,
        enforceBiometric: Bool,
        promptMessage: String?,
        completion: @escaping (Result<KeyCreationResult, Error>) -> Void
    ) {
        // Use macOS config but fallback/share struct fields where applicable
        // The Pigeon schema has MacosConfig, we should use it.
        let useDeviceCredentials = macosConfig?.useDeviceCredentials ?? false
        let biometryCurrentSet = macosConfig?.biometryCurrentSet ?? false
        let signatureType = macosConfig?.signatureType ?? .rsa
        let prompt = promptMessage ?? macosConfig?.localizedReason ?? "Authenticate to create keys"

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
             // Run on bg thread
             DispatchQueue.global(qos: .userInitiated).async {
                generateBlock()
            }
        }
    }

    func createSignature(
        payload: String?,
        androidConfig: AndroidConfig?,
        iosConfig: IosConfig?,
        macosConfig: MacosConfig?,
        promptMessage: String?,
        completion: @escaping (Result<SignatureResult, Error>) -> Void
    ) {
        guard let payload = payload, let dataToSign = payload.data(using: .utf8) else {
             completion(.success(SignatureResult(signature: nil, publicKey: nil, error: "Invalid payload", code: .invalidInput)))
             return
        }
        
        let prompt = promptMessage ?? macosConfig?.localizedReason ?? "Authenticate"
        
        // Check for RSA keys (Hybrid) - similar to iOS
        if hasRsaKey() {
             performRsaSigning(dataToSign: dataToSign, prompt: prompt, completion: completion)
        } else {
             performEcSigning(dataToSign: dataToSign, prompt: prompt, completion: completion)
        }
    }

    func decrypt(
        payload: String?,
        androidConfig: AndroidConfig?,
        iosConfig: IosConfig?,
        macosConfig: MacosConfig?,
        promptMessage: String?,
        completion: @escaping (Result<DecryptResult, Error>) -> Void
    ) {
        guard let payload = payload else {
             completion(.success(DecryptResult(decryptedData: nil, error: "Payload is required", code: .invalidInput)))
             return
        }
        let prompt = promptMessage ?? macosConfig?.localizedReason ?? "Authenticate"
        
        if hasRsaKey() {
             performRsaDecryption(payload: payload, prompt: prompt, completion: completion)
        } else {
             performEcDecryption(payload: payload, prompt: prompt, completion: completion)
        }
    }

    func deleteKeys() throws -> Bool {
        deleteExistingKeys()
        return true
    }

    func biometricKeyExists(checkValidity: Bool, completion: @escaping (Result<Bool, Error>) -> Void) {
        let ecTag = Constants.ecKeyAlias
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: ecTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: false
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        completion(.success(status == errSecSuccess))
    }

    // MARK: - Private Logic (Shared with iOS mostly)
    
    private func performKeyGeneration(
        useDeviceCredentials: Bool,
        biometryCurrentSet: Bool,
        signatureType: SignatureType,
        keyFormat: KeyFormat,
        completion: @escaping (Result<KeyCreationResult, Error>) -> Void
    ) {
        // macOS secure enclave access control might differ slightly in flags availability but usually matches iOS
        var flags: SecAccessControlCreateFlags = .privateKeyUsage
        if useDeviceCredentials {
             flags.insert(.userPresence)
        } else if biometryCurrentSet {
             flags.insert(.biometryCurrentSet)
        } else {
             flags.insert(.biometryAny)
        }
        
        guard let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags, nil) else {
            completion(.success(KeyCreationResult(publicKey: nil, error: "Failed to create access control", code: .unknown)))
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
             completion(.success(KeyCreationResult(publicKey: nil, error: "EC Key Gen Error: \(msg)", code: .unknown)))
             return
        }
        
        if biometryCurrentSet { DomainState.saveCurrent() }
        InvalidationSetting.save(biometryCurrentSet)
        
        guard let ecPublicKey = SecKeyCopyPublicKey(ecPrivateKey) else {
             completion(.success(KeyCreationResult(publicKey: nil, error: "EC Pub Key Error", code: .unknown)))
             return
        }

        if signatureType == .ecdsa {
             let keyStr = formatKey(ecPublicKey, format: keyFormat)
             completion(.success(KeyCreationResult(publicKey: keyStr, error: nil, code: .success)))
             return
        }
        
        // Hybrid RSA
        // Check encryption support
        guard SecKeyIsAlgorithmSupported(ecPublicKey, .encrypt, .eciesEncryptionStandardX963SHA256AESGCM) else {
             completion(.success(KeyCreationResult(publicKey: nil, error: "ECIES not supported", code: .unknown)))
             return
        }

        // Generate RSA Key
        let rsaAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]
        ]
        guard let rsaPrivateKey = SecKeyCreateRandomKey(rsaAttributes as CFDictionary, &error) else {
             completion(.success(KeyCreationResult(publicKey: nil, error: "RSA Gen Error", code: .unknown)))
             return
        }
        
        // Wrap RSA Private Key
        guard let rsaPrivateData = SecKeyCopyExternalRepresentation(rsaPrivateKey, &error) as Data?,
              let encryptedRsa = SecKeyCreateEncryptedData(ecPublicKey, .eciesEncryptionStandardX963SHA256AESGCM, rsaPrivateData as CFData, &error) as Data? else {
             completion(.success(KeyCreationResult(publicKey: nil, error: "RSA Wrapping Error", code: .unknown)))
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
             completion(.success(KeyCreationResult(publicKey: nil, error: "RSA Pub Key Error", code: .unknown)))
             return
        }
        
        let keyStr = formatKey(rsaPublicKey, format: keyFormat)
        completion(.success(KeyCreationResult(publicKey: keyStr, error: nil, code: .success)))
    }
    
     private func performRsaSigning(dataToSign: Data, prompt: String, completion: @escaping (Result<SignatureResult, Error>) -> Void) {
        guard let rsaPrivateKey = unwrapRsaKey(prompt: prompt) else {
             completion(.success(SignatureResult(signature: nil, publicKey: nil, error: "Failed to access/unwrap RSA key", code: .unknown)))
             return
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(rsaPrivateKey, .rsaSignatureMessagePKCS1v15SHA256, dataToSign as CFData, &error) as Data? else {
             let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown"
             completion(.success(SignatureResult(signature: nil, publicKey: nil, error: "Signing Error: \(msg)", code: .unknown)))
             return
        }
        
        guard let pub = SecKeyCopyPublicKey(rsaPrivateKey) else {
             completion(.success(SignatureResult(signature: nil, publicKey: nil, error: "Pub Key Error", code: .unknown)))
             return
        }
        
        completion(.success(SignatureResult(
            signature: signature.base64EncodedString(),
            publicKey: formatKey(pub, format: .base64),
            error: nil,
            code: .success
        )))
    }
    
    private func performEcSigning(dataToSign: Data, prompt: String, completion: @escaping (Result<SignatureResult, Error>) -> Void) {
        guard let ecKey = getEcPrivateKey(prompt: prompt) else {
             completion(.success(SignatureResult(signature: nil, publicKey: nil, error: "EC Key not found or auth failed", code: .unknown)))
             return
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(ecKey, .ecdsaSignatureMessageX962SHA256, dataToSign as CFData, &error) as Data? else {
              let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown"
               completion(.success(SignatureResult(signature: nil, publicKey: nil, error: "Signing Error: \(msg)", code: .unknown)))
              return
        }
         guard let pub = SecKeyCopyPublicKey(ecKey) else {
              completion(.success(SignatureResult(signature: nil, publicKey: nil, error: "Pub Key Error", code: .unknown)))
             return
        }
        
        completion(.success(SignatureResult(
            signature: signature.base64EncodedString(),
            publicKey: formatKey(pub, format: .base64),
            error: nil,
            code: .success
        )))
    }
    
    private func performRsaDecryption(payload: String, prompt: String, completion: @escaping (Result<DecryptResult, Error>) -> Void) {
        guard let rsaPrivateKey = unwrapRsaKey(prompt: prompt) else {
              completion(.success(DecryptResult(decryptedData: nil, error: "Failed to access/unwrap RSA key", code: .unknown)))
              return
        }
        
        var error: Unmanaged<CFError>?
        guard let encryptedData = Data(base64Encoded: payload, options: .ignoreUnknownCharacters) else {
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
    
    private func performEcDecryption(payload: String, prompt: String, completion: @escaping (Result<DecryptResult, Error>) -> Void) {
         guard let ecKey = getEcPrivateKey(prompt: prompt) else {
               completion(.success(DecryptResult(decryptedData: nil, error: "EC Key not found or auth failed", code: .unknown)))
              return
        }
        
        var error: Unmanaged<CFError>?
        guard let encryptedData = Data(base64Encoded: payload, options: .ignoreUnknownCharacters) else {
             completion(.success(DecryptResult(decryptedData: nil, error: "Invalid payload", code: .invalidInput)))
             return
        }

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
              
        guard let ecKey = getEcPrivateKey(prompt: prompt) else { return nil }
        
        var error: Unmanaged<CFError>?
        guard let rsaData = SecKeyCreateDecryptedData(ecKey, .eciesEncryptionStandardX963SHA256AESGCM, wrappedData as CFData, &error) as Data? else {
            return nil
        }
        
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048
        ]
        return SecKeyCreateWithData(rsaData as CFData, attrs as CFDictionary, nil)
    }

    private func formatKey(_ key: SecKey, format: KeyFormat) -> String {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(key, &error) as Data? else { return "" }
        if format == .pem {
             let base64 = data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
             return "-----BEGIN PUBLIC KEY-----\n\(base64)\n-----END PUBLIC KEY-----"
        }
        return data.base64EncodedString()
    }
}
