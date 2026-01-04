import Foundation
import CoreBluetooth
import CryptoKit

/// BLE UUIDs for BlueGate service
/// Using Bluetooth Base UUID: 0000xxxx-0000-1000-8000-00805F9B34FB
struct BLEConstants {
    // Helper to create full UUID from short form
    private static func uuid(_ short: String) -> CBUUID {
        return CBUUID(string: "0000\(short)-0000-1000-8000-00805F9B34FB")
    }

    // Service UUID (using custom UUID from trouble-host gatt_service macro)
    static let serviceUUID = CBUUID(string: "6a7e6a7e-4929-42d0-0000-fcc5a35e13f1")

    // Authentication characteristics
    static let nonceUUID = uuid("0100")
    static let authenticateUUID = uuid("0101")
    static let clientPubkeyUUID = uuid("0102")
    static let clientNonceUUID = uuid("0103")
    static let clientKeyAckUUID = uuid("0104")
    static let authenticateAckUUID = uuid("0105")
    static let actionUUID = uuid("0106")
    static let payloadUUID = uuid("0107")
    static let permUUID = uuid("0108")

    // Management characteristics
    static let managementUUID = uuid("1100")
    static let managementKeyUUID = uuid("1101")
    static let managementParamIdUUID = uuid("1102")
    static let managementParamValUUID = uuid("1103")
    static let managementNameUUID = uuid("1104")
    static let managementResultUUID = uuid("1105")

    // Management action codes
    static let mgmtAddKey: UInt8 = 0x01
    static let mgmtDelKey: UInt8 = 0x02
    static let mgmtGetKey: UInt8 = 0x03
    static let mgmtSetParam: UInt8 = 0x10
    static let mgmtGetParam: UInt8 = 0x11
    static let mgmtSetName: UInt8 = 0x20

    // Management result codes
    static let mgmtOk: UInt8 = 0x00
    static let mgmtErrNotAdmin: UInt8 = 0x01
    static let mgmtErrFlash: UInt8 = 0x02
    static let mgmtErrNotFound: UInt8 = 0x03
    static let mgmtErrInvalid: UInt8 = 0x04

    // Permission flags
    static let permAdmin: UInt8 = 0x80

    // Auth action codes
    static let actionOpen: UInt16 = 0x01
    static let actionOpenHold: UInt16 = 0x02
    static let actionClose: UInt16 = 0x03
    static let actionAdmin: UInt16 = 0x80
}

/// Represents a discovered BlueGate device
class BlueGateDevice: Identifiable, ObservableObject {
    let id: UUID
    let peripheral: CBPeripheral
    @Published var name: String
    @Published var rssi: Int
    @Published var state: DeviceState = .disconnected
    @Published var isAdmin: Bool = false
    @Published var errorMessage: String?

    var characteristics: [CBUUID: CBCharacteristic] = [:]

    // Persistent admin rights storage key
    private var adminRightsKey: String { "adminRights_\(id.uuidString)" }

    // Admin rights persisted to UserDefaults
    var hasAdminRights: Bool {
        get { UserDefaults.standard.bool(forKey: adminRightsKey) }
        set {
            UserDefaults.standard.set(newValue, forKey: adminRightsKey)
            objectWillChange.send()
        }
    }

    enum DeviceState {
        case disconnected
        case connecting
        case connected
        case authenticating
        case authenticated
        case error
    }

    init(peripheral: CBPeripheral, name: String, rssi: Int) {
        self.id = peripheral.identifier
        self.peripheral = peripheral
        self.name = name
        self.rssi = rssi
    }
}

/// Manages BLE scanning, connection, and communication
class BLEManager: NSObject, ObservableObject {
    private var centralManager: CBCentralManager!

    @Published var devices: [UUID: BlueGateDevice] = [:]
    @Published var isScanning: Bool = false
    @Published var bluetoothState: CBManagerState = .unknown

    private var pendingWrites: [CBUUID: (Result<Void, Error>) -> Void] = [:]
    private var pendingReads: [CBUUID: (Result<Data?, Error>) -> Void] = [:]
    private var keyManager: KeyManager?

    override init() {
        super.init()
        centralManager = CBCentralManager(delegate: self, queue: nil)
    }

    func setKeyManager(_ keyManager: KeyManager) {
        self.keyManager = keyManager
    }

    func startScanning() {
        guard centralManager.state == .poweredOn else { return }
        isScanning = true
        centralManager.scanForPeripherals(
            withServices: [BLEConstants.serviceUUID],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
        )
    }

    func stopScanning() {
        centralManager.stopScan()
        isScanning = false
    }

    func connect(to device: BlueGateDevice) {
        device.state = .connecting
        centralManager.connect(device.peripheral, options: nil)
    }

    func disconnect(from device: BlueGateDevice) {
        centralManager.cancelPeripheralConnection(device.peripheral)
        device.state = .disconnected
    }

    /// Authenticate with the device (Open button flow)
    func authenticate(device: BlueGateDevice, completion: @escaping (Result<Bool, Error>) -> Void) {
        guard let keyManager = keyManager else {
            completion(.failure(BLEError.noKeyManager))
            return
        }

        device.state = .authenticating
        device.errorMessage = nil

        Task {
            do {
                // Step 1: Write client public key
                let pubKey = keyManager.publicKeyCompressed
                guard let clientPubkeyChar = device.characteristics[BLEConstants.clientPubkeyUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(pubKey, to: clientPubkeyChar, peripheral: device.peripheral)

                // Step 2: Read client_key_ack
                guard let keyAckChar = device.characteristics[BLEConstants.clientKeyAckUUID] else {
                    throw BLEError.characteristicNotFound
                }
                let keyAckData = try await readValue(from: keyAckChar, peripheral: device.peripheral)
                guard let keyAck = keyAckData?.first, keyAck != 0 else {
                    device.state = .error
                    device.errorMessage = "Key not authorized"
                    // Key is no longer authorized - remove admin rights
                    device.hasAdminRights = false
                    device.isAdmin = false
                    completion(.failure(BLEError.keyNotAuthorized))
                    return
                }

                // Read permissions
                if let permChar = device.characteristics[BLEConstants.permUUID] {
                    let permData = try await readValue(from: permChar, peripheral: device.peripheral)
                    if let perm = permData?.first {
                        device.isAdmin = (perm & BLEConstants.permAdmin) == BLEConstants.permAdmin
                        // Update persistent admin rights (could be granted or revoked)
                        device.hasAdminRights = device.isAdmin
                    }
                }

                // Step 3: Read server nonce
                guard let nonceChar = device.characteristics[BLEConstants.nonceUUID] else {
                    throw BLEError.characteristicNotFound
                }
                guard let serverNonce = try await readValue(from: nonceChar, peripheral: device.peripheral),
                      serverNonce.count == 32 else {
                    throw BLEError.invalidData
                }

                // Step 4: Generate and write client nonce
                var clientNonce = Data(count: 32)
                _ = clientNonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

                guard let clientNonceChar = device.characteristics[BLEConstants.clientNonceUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(clientNonce, to: clientNonceChar, peripheral: device.peripheral)

                // Step 5: Calculate digest and sign
                var digestData = Data()
                digestData.append(serverNonce)
                digestData.append(clientNonce)
                let digest = SHA256.hash(data: digestData)
                let digestBytes = Data(digest)

                guard let signature = keyManager.signDigest(digestBytes) else {
                    throw BLEError.signingFailed
                }

                // Step 6: Write signature
                guard let authChar = device.characteristics[BLEConstants.authenticateUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(signature, to: authChar, peripheral: device.peripheral)

                // Step 7: Check authenticate_ack
                guard let authAckChar = device.characteristics[BLEConstants.authenticateAckUUID] else {
                    throw BLEError.characteristicNotFound
                }
                let authAckData = try await readValue(from: authAckChar, peripheral: device.peripheral)
                guard let authAck = authAckData?.first, authAck != 0 else {
                    device.state = .error
                    device.errorMessage = "Authentication failed"
                    completion(.failure(BLEError.authenticationFailed))
                    return
                }

                device.state = .authenticated
                completion(.success(true))

            } catch {
                device.state = .error
                device.errorMessage = error.localizedDescription
                completion(.failure(error))
            }
        }
    }

    // MARK: - Auth Action

    /// Set auth_action before authentication (1=open, 2=open+hold, 3=close, 128=admin mode)
    func setAuthAction(device: BlueGateDevice, action: UInt16) async throws {
        guard let actionChar = device.characteristics[BLEConstants.actionUUID] else {
            throw BLEError.characteristicNotFound
        }
        var val = action.littleEndian
        let data = Data(bytes: &val, count: 2)
        try await writeValue(data, to: actionChar, peripheral: device.peripheral)
    }

    /// Read the current gate name from management_name characteristic
    func getGateName(device: BlueGateDevice) async throws -> String {
        guard let nameChar = device.characteristics[BLEConstants.managementNameUUID] else {
            throw BLEError.characteristicNotFound
        }
        let data = try await readValue(from: nameChar, peripheral: device.peripheral)
        guard let nameData = data else {
            return ""
        }
        // Find null terminator
        let len = nameData.firstIndex(of: 0) ?? nameData.count
        return String(data: nameData.prefix(len), encoding: .utf8) ?? ""
    }

    // MARK: - Management Operations

    func addKey(device: BlueGateDevice, keyHex: String, completion: @escaping (Result<Void, Error>) -> Void) {
        guard device.isAdmin else {
            completion(.failure(BLEError.notAdmin))
            return
        }

        guard let keyData = Data(hexString: keyHex), keyData.count == 33 else {
            completion(.failure(BLEError.invalidKeyFormat))
            return
        }

        Task {
            do {
                // Write key
                guard let keyChar = device.characteristics[BLEConstants.managementKeyUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(keyData, to: keyChar, peripheral: device.peripheral)

                // Trigger add action
                guard let mgmtChar = device.characteristics[BLEConstants.managementUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(Data([BLEConstants.mgmtAddKey]), to: mgmtChar, peripheral: device.peripheral)

                // Check result
                guard let resultChar = device.characteristics[BLEConstants.managementResultUUID] else {
                    throw BLEError.characteristicNotFound
                }
                let result = try await readValue(from: resultChar, peripheral: device.peripheral)

                if result?.first == BLEConstants.mgmtOk {
                    completion(.success(()))
                } else {
                    completion(.failure(BLEError.managementFailed(result?.first ?? 0xFF)))
                }
            } catch {
                completion(.failure(error))
            }
        }
    }

    func getParameter(device: BlueGateDevice, slot: UInt8, completion: @escaping (Result<UInt32, Error>) -> Void) {
        guard device.isAdmin else {
            completion(.failure(BLEError.notAdmin))
            return
        }

        Task {
            do {
                // Write slot ID
                guard let slotChar = device.characteristics[BLEConstants.managementParamIdUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(Data([slot]), to: slotChar, peripheral: device.peripheral)

                // Trigger get action
                guard let mgmtChar = device.characteristics[BLEConstants.managementUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(Data([BLEConstants.mgmtGetParam]), to: mgmtChar, peripheral: device.peripheral)

                // Check result
                guard let resultChar = device.characteristics[BLEConstants.managementResultUUID] else {
                    throw BLEError.characteristicNotFound
                }
                let result = try await readValue(from: resultChar, peripheral: device.peripheral)

                if result?.first == BLEConstants.mgmtOk {
                    // Read the value from management_param_val
                    guard let valChar = device.characteristics[BLEConstants.managementParamValUUID] else {
                        throw BLEError.characteristicNotFound
                    }
                    let valData = try await readValue(from: valChar, peripheral: device.peripheral)

                    if let data = valData, data.count >= 4 {
                        let value = data.withUnsafeBytes { $0.load(as: UInt32.self) }
                        completion(.success(UInt32(littleEndian: value)))
                    } else {
                        completion(.failure(BLEError.invalidData))
                    }
                } else {
                    completion(.failure(BLEError.managementFailed(result?.first ?? 0xFF)))
                }
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Get key at index. Returns (keyData, totalCount) on success.
    func getKey(device: BlueGateDevice, index: UInt32, completion: @escaping (Result<(Data, UInt32), Error>) -> Void) {
        guard device.isAdmin else {
            completion(.failure(BLEError.notAdmin))
            return
        }

        Task {
            do {
                // Write index to management_param_val (little-endian u32)
                guard let valChar = device.characteristics[BLEConstants.managementParamValUUID] else {
                    throw BLEError.characteristicNotFound
                }
                var idx = index.littleEndian
                let indexData = Data(bytes: &idx, count: 4)
                try await writeValue(indexData, to: valChar, peripheral: device.peripheral)

                // Trigger get key action
                guard let mgmtChar = device.characteristics[BLEConstants.managementUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(Data([BLEConstants.mgmtGetKey]), to: mgmtChar, peripheral: device.peripheral)

                // Check result
                guard let resultChar = device.characteristics[BLEConstants.managementResultUUID] else {
                    throw BLEError.characteristicNotFound
                }
                let result = try await readValue(from: resultChar, peripheral: device.peripheral)

                if result?.first == BLEConstants.mgmtOk {
                    // Read the key from management_key
                    guard let keyChar = device.characteristics[BLEConstants.managementKeyUUID] else {
                        throw BLEError.characteristicNotFound
                    }
                    let keyData = try await readValue(from: keyChar, peripheral: device.peripheral)

                    // Read total count from management_param_val
                    let countData = try await readValue(from: valChar, peripheral: device.peripheral)

                    guard let key = keyData, key.count == 33 else {
                        throw BLEError.invalidData
                    }

                    var count: UInt32 = 0
                    if let data = countData, data.count >= 4 {
                        count = data.withUnsafeBytes { $0.load(as: UInt32.self) }
                        count = UInt32(littleEndian: count)
                    }

                    completion(.success((key, count)))
                } else {
                    completion(.failure(BLEError.managementFailed(result?.first ?? 0xFF)))
                }
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Get all keys from the device. Returns array of 33-byte key data.
    func getAllKeys(device: BlueGateDevice, completion: @escaping (Result<[Data], Error>) -> Void) {
        guard device.isAdmin else {
            completion(.failure(BLEError.notAdmin))
            return
        }

        Task {
            var keys: [Data] = []
            var index: UInt32 = 0

            // Get first key to determine count
            do {
                guard let valChar = device.characteristics[BLEConstants.managementParamValUUID] else {
                    throw BLEError.characteristicNotFound
                }
                var idx = index.littleEndian
                let indexData = Data(bytes: &idx, count: 4)
                try await writeValue(indexData, to: valChar, peripheral: device.peripheral)

                guard let mgmtChar = device.characteristics[BLEConstants.managementUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(Data([BLEConstants.mgmtGetKey]), to: mgmtChar, peripheral: device.peripheral)

                guard let resultChar = device.characteristics[BLEConstants.managementResultUUID] else {
                    throw BLEError.characteristicNotFound
                }
                let result = try await readValue(from: resultChar, peripheral: device.peripheral)

                // Read count from param_val
                let countData = try await readValue(from: valChar, peripheral: device.peripheral)
                var totalCount: UInt32 = 0
                if let data = countData, data.count >= 4 {
                    totalCount = data.withUnsafeBytes { $0.load(as: UInt32.self) }
                    totalCount = UInt32(littleEndian: totalCount)
                }

                if result?.first == BLEConstants.mgmtOk {
                    // Read first key
                    guard let keyChar = device.characteristics[BLEConstants.managementKeyUUID] else {
                        throw BLEError.characteristicNotFound
                    }
                    if let keyData = try await readValue(from: keyChar, peripheral: device.peripheral), keyData.count == 33 {
                        keys.append(keyData)
                    }

                    // Read remaining keys
                    for i in 1..<totalCount {
                        var idx = i.littleEndian
                        let indexData = Data(bytes: &idx, count: 4)
                        try await writeValue(indexData, to: valChar, peripheral: device.peripheral)
                        try await writeValue(Data([BLEConstants.mgmtGetKey]), to: mgmtChar, peripheral: device.peripheral)

                        let result = try await readValue(from: resultChar, peripheral: device.peripheral)
                        if result?.first == BLEConstants.mgmtOk {
                            if let keyData = try await readValue(from: keyChar, peripheral: device.peripheral), keyData.count == 33 {
                                keys.append(keyData)
                            }
                        }
                    }
                }

                completion(.success(keys))
            } catch {
                completion(.failure(error))
            }
        }
    }

    func deleteKey(device: BlueGateDevice, keyHex: String, completion: @escaping (Result<Void, Error>) -> Void) {
        guard device.isAdmin else {
            completion(.failure(BLEError.notAdmin))
            return
        }

        guard let keyData = Data(hexString: keyHex), keyData.count == 33 else {
            completion(.failure(BLEError.invalidKeyFormat))
            return
        }

        Task {
            do {
                guard let keyChar = device.characteristics[BLEConstants.managementKeyUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(keyData, to: keyChar, peripheral: device.peripheral)

                guard let mgmtChar = device.characteristics[BLEConstants.managementUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(Data([BLEConstants.mgmtDelKey]), to: mgmtChar, peripheral: device.peripheral)

                guard let resultChar = device.characteristics[BLEConstants.managementResultUUID] else {
                    throw BLEError.characteristicNotFound
                }
                let result = try await readValue(from: resultChar, peripheral: device.peripheral)

                if result?.first == BLEConstants.mgmtOk {
                    completion(.success(()))
                } else {
                    completion(.failure(BLEError.managementFailed(result?.first ?? 0xFF)))
                }
            } catch {
                completion(.failure(error))
            }
        }
    }

    func setParameter(device: BlueGateDevice, slot: UInt8, value: UInt32, completion: @escaping (Result<Void, Error>) -> Void) {
        guard device.isAdmin else {
            completion(.failure(BLEError.notAdmin))
            return
        }

        Task {
            do {
                // Write slot ID
                guard let slotChar = device.characteristics[BLEConstants.managementParamIdUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(Data([slot]), to: slotChar, peripheral: device.peripheral)

                // Write value (little-endian)
                guard let valChar = device.characteristics[BLEConstants.managementParamValUUID] else {
                    throw BLEError.characteristicNotFound
                }
                var val = value.littleEndian
                let valData = Data(bytes: &val, count: 4)
                try await writeValue(valData, to: valChar, peripheral: device.peripheral)

                // Trigger set action
                guard let mgmtChar = device.characteristics[BLEConstants.managementUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(Data([BLEConstants.mgmtSetParam]), to: mgmtChar, peripheral: device.peripheral)

                // Check result
                guard let resultChar = device.characteristics[BLEConstants.managementResultUUID] else {
                    throw BLEError.characteristicNotFound
                }
                let result = try await readValue(from: resultChar, peripheral: device.peripheral)

                if result?.first == BLEConstants.mgmtOk {
                    completion(.success(()))
                } else {
                    completion(.failure(BLEError.managementFailed(result?.first ?? 0xFF)))
                }
            } catch {
                completion(.failure(error))
            }
        }
    }

    func setName(device: BlueGateDevice, name: String, completion: @escaping (Result<Void, Error>) -> Void) {
        guard device.isAdmin else {
            completion(.failure(BLEError.notAdmin))
            return
        }

        Task {
            do {
                // Prepare name data (null-terminated, padded to 64 bytes)
                var nameData = Data(name.utf8)
                nameData.append(0) // null terminator
                while nameData.count < 64 {
                    nameData.append(0)
                }
                nameData = nameData.prefix(64)

                guard let nameChar = device.characteristics[BLEConstants.managementNameUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(nameData, to: nameChar, peripheral: device.peripheral)

                guard let mgmtChar = device.characteristics[BLEConstants.managementUUID] else {
                    throw BLEError.characteristicNotFound
                }
                try await writeValue(Data([BLEConstants.mgmtSetName]), to: mgmtChar, peripheral: device.peripheral)

                guard let resultChar = device.characteristics[BLEConstants.managementResultUUID] else {
                    throw BLEError.characteristicNotFound
                }
                let result = try await readValue(from: resultChar, peripheral: device.peripheral)

                if result?.first == BLEConstants.mgmtOk {
                    completion(.success(()))
                } else {
                    completion(.failure(BLEError.managementFailed(result?.first ?? 0xFF)))
                }
            } catch {
                completion(.failure(error))
            }
        }
    }

    // MARK: - Async BLE Operations

    private func writeValue(_ data: Data, to characteristic: CBCharacteristic, peripheral: CBPeripheral) async throws {
        // Check max write length for withResponse
        let maxLenWithResponse = peripheral.maximumWriteValueLength(for: .withResponse)
        let maxLenWithoutResponse = peripheral.maximumWriteValueLength(for: .withoutResponse)
        print("[BLE] Writing \(data.count) bytes (max w/resp: \(maxLenWithResponse), w/o resp: \(maxLenWithoutResponse)) to \(characteristic.uuid)")

        // For large writes, use withoutResponse if characteristic supports it and data fits
        let useWithoutResponse = data.count > 20 &&
            data.count <= maxLenWithoutResponse &&
            characteristic.properties.contains(.writeWithoutResponse)

        if useWithoutResponse {
            print("[BLE] Using writeWithoutResponse for \(characteristic.uuid)")
            peripheral.writeValue(data, for: characteristic, type: .withoutResponse)
            // Small delay to ensure write completes
            try await Task.sleep(nanoseconds: 50_000_000) // 50ms
            return
        }

        return try await withCheckedThrowingContinuation { continuation in
            pendingWrites[characteristic.uuid] = { result in
                switch result {
                case .success:
                    print("[BLE] Write success to \(characteristic.uuid)")
                    continuation.resume()
                case .failure(let error):
                    print("[BLE] Write error to \(characteristic.uuid): \(error.localizedDescription)")
                    continuation.resume(throwing: error)
                }
            }
            peripheral.writeValue(data, for: characteristic, type: .withResponse)
        }
    }

    private func readValue(from characteristic: CBCharacteristic, peripheral: CBPeripheral) async throws -> Data? {
        print("[BLE] Reading from \(characteristic.uuid)")
        return try await withCheckedThrowingContinuation { continuation in
            pendingReads[characteristic.uuid] = { result in
                switch result {
                case .success(let data):
                    print("[BLE] Read success from \(characteristic.uuid): \(data?.count ?? 0) bytes")
                    continuation.resume(returning: data)
                case .failure(let error):
                    print("[BLE] Read error from \(characteristic.uuid): \(error.localizedDescription)")
                    continuation.resume(throwing: error)
                }
            }
            peripheral.readValue(for: characteristic)
        }
    }
}

// MARK: - CBCentralManagerDelegate

extension BLEManager: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        bluetoothState = central.state
        if central.state == .poweredOn {
            startScanning()
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let name = advertisementData[CBAdvertisementDataLocalNameKey] as? String ?? peripheral.name ?? "Unknown"

        DispatchQueue.main.async {
            if let existing = self.devices[peripheral.identifier] {
                existing.rssi = RSSI.intValue
                existing.name = name
            } else {
                let device = BlueGateDevice(peripheral: peripheral, name: name, rssi: RSSI.intValue)
                self.devices[peripheral.identifier] = device
            }
        }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.delegate = self
        // Check the maximum write length (triggers MTU negotiation on iOS)
        let maxWriteLen = peripheral.maximumWriteValueLength(for: .withResponse)
        print("[BLE] Connected, max write length: \(maxWriteLen)")
        peripheral.discoverServices([BLEConstants.serviceUUID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        if let device = devices[peripheral.identifier] {
            device.state = .error
            device.errorMessage = error?.localizedDescription ?? "Connection failed"
        }
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        if let device = devices[peripheral.identifier] {
            device.state = .disconnected
            device.characteristics.removeAll()
        }
    }
}

// MARK: - CBPeripheralDelegate

extension BLEManager: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil, let services = peripheral.services else { return }

        for service in services {
            if service.uuid == BLEConstants.serviceUUID {
                peripheral.discoverCharacteristics(nil, for: service)
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard error == nil, let characteristics = service.characteristics else { return }

        if let device = devices[peripheral.identifier] {
            for char in characteristics {
                device.characteristics[char.uuid] = char
                print("[BLE] Found characteristic: \(char.uuid), properties: \(char.properties.rawValue)")
            }
            // Check MTU after characteristics discovered
            let maxWriteLen = peripheral.maximumWriteValueLength(for: .withResponse)
            print("[BLE] Ready, max write length: \(maxWriteLen)")
            device.state = .connected
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        if let completion = pendingWrites.removeValue(forKey: characteristic.uuid) {
            if let error = error {
                completion(.failure(error))
            } else {
                completion(.success(()))
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        // Handle pending reads
        if let completion = pendingReads.removeValue(forKey: characteristic.uuid) {
            if let error = error {
                completion(.failure(error))
            } else {
                completion(.success(characteristic.value))
            }
        }
        // Note: notifications would also trigger this callback, but without a pending read they're ignored
    }
}

// MARK: - Errors

enum BLEError: LocalizedError {
    case noKeyManager
    case characteristicNotFound
    case keyNotAuthorized
    case authenticationFailed
    case signingFailed
    case invalidData
    case notAdmin
    case invalidKeyFormat
    case managementFailed(UInt8)

    var errorDescription: String? {
        switch self {
        case .noKeyManager: return "Key manager not initialized"
        case .characteristicNotFound: return "BLE characteristic not found"
        case .keyNotAuthorized: return "Key not authorized on this device"
        case .authenticationFailed: return "Authentication failed"
        case .signingFailed: return "Failed to sign challenge"
        case .invalidData: return "Invalid data received"
        case .notAdmin: return "Admin permission required"
        case .invalidKeyFormat: return "Invalid key format (expected 33 bytes hex)"
        case .managementFailed(let code):
            switch code {
            case BLEConstants.mgmtErrNotAdmin: return "Not admin"
            case BLEConstants.mgmtErrFlash: return "Flash storage error"
            case BLEConstants.mgmtErrNotFound: return "Key not found"
            case BLEConstants.mgmtErrInvalid: return "Invalid operation"
            default: return "Management error: \(code)"
            }
        }
    }
}

// MARK: - Data Extension

extension Data {
    init?(hexString: String) {
        let hex = hexString.replacingOccurrences(of: " ", with: "")
        guard hex.count % 2 == 0 else { return nil }

        var data = Data()
        var index = hex.startIndex

        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }

        self = data
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
