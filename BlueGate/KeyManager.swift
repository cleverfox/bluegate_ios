import Foundation
import Security
import CryptoKit

/// Manages secp256r1 keypair using Secure Enclave when available
class KeyManager: ObservableObject {
    private let keyTag = "org.cleverfox.bluegate.key"

    @Published var publicKeyHex: String = ""
    @Published var publicKeyCompressed: Data = Data()
    @Published var isSecureEnclaveAvailable: Bool = false
    @Published var errorMessage: String?

    private var privateKey: SecKey?

    init() {
        checkSecureEnclaveAvailability()
        loadOrGenerateKey()
    }

    private func checkSecureEnclaveAvailability() {
        // Check if device supports Secure Enclave
        if #available(iOS 13.0, *) {
            isSecureEnclaveAvailable = SecureEnclave.isAvailable
        } else {
            isSecureEnclaveAvailable = false
        }
    }

    private func loadOrGenerateKey() {
        // Try to load existing key
        if let key = loadKey() {
            privateKey = key
            updatePublicKey()
            return
        }

        // Generate new key
        generateKey()
    }

    private func loadKey() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecSuccess {
            return (item as! SecKey)
        }
        return nil
    }

    private func generateKey() {
        var error: Unmanaged<CFError>?

        // Access control for Secure Enclave - key cannot be extracted
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            isSecureEnclaveAvailable ? [.privateKeyUsage] : [],
            &error
        ) else {
            errorMessage = "Failed to create access control: \(error?.takeRetainedValue().localizedDescription ?? "unknown")"
            return
        }

        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrApplicationTag as String: keyTag,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: accessControl
            ]
        ]

        // Use Secure Enclave if available
        if isSecureEnclaveAvailable {
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }

        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            errorMessage = "Failed to generate key: \(error?.takeRetainedValue().localizedDescription ?? "unknown")"
            return
        }

        privateKey = key
        updatePublicKey()
    }

    private func updatePublicKey() {
        guard let privateKey = privateKey,
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            errorMessage = "Failed to get public key"
            return
        }

        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            errorMessage = "Failed to export public key: \(error?.takeRetainedValue().localizedDescription ?? "unknown")"
            return
        }

        // Convert uncompressed point (65 bytes: 0x04 + X + Y) to compressed (33 bytes: 0x02/0x03 + X)
        publicKeyCompressed = compressPublicKey(publicKeyData)
        publicKeyHex = publicKeyCompressed.map { String(format: "%02x", $0) }.joined()
    }

    /// Compress uncompressed SEC1 public key (65 bytes) to compressed format (33 bytes)
    private func compressPublicKey(_ uncompressed: Data) -> Data {
        guard uncompressed.count == 65 && uncompressed[0] == 0x04 else {
            // Already compressed or invalid
            return uncompressed
        }

        let x = uncompressed.subdata(in: 1..<33)
        let y = uncompressed.subdata(in: 33..<65)

        // Determine prefix based on Y coordinate parity
        let prefix: UInt8 = (y.last! & 0x01) == 0 ? 0x02 : 0x03

        var compressed = Data([prefix])
        compressed.append(x)
        return compressed
    }

    /// Get shortened display string for public key
    var publicKeyDisplay: String {
        guard publicKeyHex.count >= 16 else { return publicKeyHex }
        let start = publicKeyHex.prefix(8)
        let end = publicKeyHex.suffix(8)
        return "\(start)...\(end)"
    }

    /// Sign data using the private key
    func sign(data: Data) -> Data? {
        guard let privateKey = privateKey else {
            errorMessage = "No private key available"
            return nil
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            errorMessage = "Signing failed: \(error?.takeRetainedValue().localizedDescription ?? "unknown")"
            return nil
        }

        // Convert DER signature to raw (r || s) format
        return derToRaw(signature)
    }

    /// Sign a prehashed digest (32 bytes) - for our protocol we hash first then sign the hash
    func signDigest(_ digest: Data) -> Data? {
        guard let key = privateKey else {
            errorMessage = "No private key available"
            return nil
        }

        // Use raw signing (no additional hashing)
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            &error
        ) as Data? else {
            errorMessage = "Signing failed: \(error?.takeRetainedValue().localizedDescription ?? "unknown")"
            return nil
        }

        // Convert DER signature to raw (r || s) format
        return derToRaw(signature)
    }

    /// Convert DER-encoded ECDSA signature to raw (r || s) format
    private func derToRaw(_ der: Data) -> Data? {
        // DER format: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>
        guard der.count >= 8, der[0] == 0x30 else { return nil }

        var offset = 2 // Skip 0x30 and length

        // Read R
        guard der[offset] == 0x02 else { return nil }
        offset += 1
        let rLen = Int(der[offset])
        offset += 1
        var r = der.subdata(in: offset..<(offset + rLen))
        offset += rLen

        // Read S
        guard der[offset] == 0x02 else { return nil }
        offset += 1
        let sLen = Int(der[offset])
        offset += 1
        var s = der.subdata(in: offset..<(offset + sLen))

        // Remove leading zeros and pad to 32 bytes
        while r.count > 32 && r[0] == 0x00 { r = r.dropFirst() }
        while s.count > 32 && s[0] == 0x00 { s = s.dropFirst() }

        // Pad to 32 bytes if needed
        while r.count < 32 { r = Data([0x00]) + r }
        while s.count < 32 { s = Data([0x00]) + s }

        return r + s
    }

}
