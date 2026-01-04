import SwiftUI

struct ContentView: View {
    @EnvironmentObject var keyManager: KeyManager
    @EnvironmentObject var bleManager: BLEManager

    @State private var adminDevice: BlueGateDevice?
    @State private var showingAlert = false
    @State private var alertMessage = ""

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Public Key Header
                PublicKeyHeader(keyManager: keyManager)

                Divider()

                // Device List
                if bleManager.bluetoothState != .poweredOn {
                    BluetoothStatusView(state: bleManager.bluetoothState)
                } else if bleManager.devices.isEmpty {
                    EmptyDevicesView(isScanning: bleManager.isScanning)
                } else {
                    DeviceListView(
                        devices: Array(bleManager.devices.values).sorted { $0.rssi > $1.rssi },
                        onOpen: openGate,
                        onAdmin: openAdmin
                    )
                }
            }
            .navigationTitle("BlueGate")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: toggleScanning) {
                        Image(systemName: bleManager.isScanning ? "antenna.radiowaves.left.and.right" : "antenna.radiowaves.left.and.right.slash")
                    }
                }
            }
            .onAppear {
                bleManager.setKeyManager(keyManager)
            }
            .sheet(item: $adminDevice) { device in
                AdminView(device: device)
                    .environmentObject(bleManager)
            }
            .alert("Error", isPresented: $showingAlert) {
                Button("OK", role: .cancel) { }
            } message: {
                Text(alertMessage)
            }
        }
    }

    private func toggleScanning() {
        if bleManager.isScanning {
            bleManager.stopScanning()
        } else {
            bleManager.startScanning()
        }
    }

    private func openGate(_ device: BlueGateDevice) {
        if device.state == .disconnected {
            bleManager.connect(to: device)
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                authenticateDevice(device)
            }
        } else if device.state == .connected {
            authenticateDevice(device)
        }
    }

    private func authenticateDevice(_ device: BlueGateDevice) {
        bleManager.authenticate(device: device) { result in
            switch result {
            case .success:
                device.lastAuthenticatedAt = Date()
                // Schedule refresh after 2.5 seconds to clear the green highlight
                DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
                    device.objectWillChange.send()
                }
                bleManager.disconnect(from: device)
            case .failure(let error):
                alertMessage = error.localizedDescription
                showingAlert = true
                bleManager.disconnect(from: device)
            }
        }
    }

    private func openAdmin(_ device: BlueGateDevice) {
        if device.state == .disconnected {
            bleManager.connect(to: device)
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                authenticateForAdmin(device)
            }
        } else if device.state == .connected {
            authenticateForAdmin(device)
        } else if device.state == .authenticated {
            setAdminModeAndOpen(device)
        }
    }

    private func authenticateForAdmin(_ device: BlueGateDevice) {
        Task {
            do {
                try await bleManager.setAuthAction(device: device, action: 128)
            } catch {
                DispatchQueue.main.async {
                    alertMessage = "Failed to set admin mode: \(error.localizedDescription)"
                    showingAlert = true
                }
                return
            }

            bleManager.authenticate(device: device) { result in
                switch result {
                case .success:
                    DispatchQueue.main.async {
                        adminDevice = device
                    }
                case .failure(let error):
                    DispatchQueue.main.async {
                        alertMessage = error.localizedDescription
                        showingAlert = true
                    }
                }
            }
        }
    }

    private func setAdminModeAndOpen(_ device: BlueGateDevice) {
        Task {
            do {
                try await bleManager.setAuthAction(device: device, action: 128)
            } catch {
                DispatchQueue.main.async {
                    alertMessage = "Failed to set admin mode: \(error.localizedDescription)"
                    showingAlert = true
                }
                return
            }

            DispatchQueue.main.async {
                adminDevice = device
            }
        }
    }
}

// MARK: - Public Key Header

struct PublicKeyHeader: View {
    @ObservedObject var keyManager: KeyManager

    var body: some View {
        VStack(spacing: 8) {
            HStack {
                Text("Your Public Key")
                    .font(.headline)

                if keyManager.isSecureEnclaveAvailable {
                    Image(systemName: "lock.shield.fill")
                        .foregroundColor(.green)
                        .help("Protected by Secure Enclave")
                }

                Spacer()
            }

            HStack {
                Text(keyManager.publicKeyDisplay)
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(.primary)

                Spacer()

                Button(action: copyToClipboard) {
                    HStack(spacing: 4) {
                        Image(systemName: "doc.on.doc")
                        Text("Copy")
                    }
                    .font(.subheadline)
                }
                .buttonStyle(.bordered)
            }

            if let error = keyManager.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
            }
        }
        .padding()
        .background(Color(.systemGroupedBackground))
    }

    private func copyToClipboard() {
        UIPasteboard.general.string = keyManager.publicKeyHex
    }
}

// MARK: - Bluetooth Status View

struct BluetoothStatusView: View {
    let state: CBManagerState

    var body: some View {
        VStack(spacing: 16) {
            Spacer()

            Image(systemName: iconName)
                .font(.system(size: 60))
                .foregroundColor(.secondary)

            Text(statusText)
                .font(.headline)
                .foregroundColor(.secondary)

            Text(statusDescription)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            Spacer()
        }
    }

    private var iconName: String {
        switch state {
        case .poweredOff: return "bluetooth.slash"
        case .unauthorized: return "hand.raised.slash"
        case .unsupported: return "xmark.circle"
        default: return "antenna.radiowaves.left.and.right.slash"
        }
    }

    private var statusText: String {
        switch state {
        case .poweredOff: return "Bluetooth is Off"
        case .unauthorized: return "Bluetooth Not Authorized"
        case .unsupported: return "Bluetooth Not Supported"
        case .resetting: return "Bluetooth Resetting"
        default: return "Bluetooth Unavailable"
        }
    }

    private var statusDescription: String {
        switch state {
        case .poweredOff: return "Please enable Bluetooth in Settings to scan for gates."
        case .unauthorized: return "Please allow Bluetooth access in Settings > Privacy > Bluetooth."
        case .unsupported: return "This device does not support Bluetooth Low Energy."
        default: return "Please wait..."
        }
    }
}

import CoreBluetooth

// MARK: - Empty Devices View

struct EmptyDevicesView: View {
    let isScanning: Bool

    var body: some View {
        VStack(spacing: 16) {
            Spacer()

            if isScanning {
                ProgressView()
                    .scaleEffect(1.5)

                Text("Scanning for gates...")
                    .font(.headline)
                    .foregroundColor(.secondary)
            } else {
                Image(systemName: "door.garage.closed")
                    .font(.system(size: 60))
                    .foregroundColor(.secondary)

                Text("No gates found")
                    .font(.headline)
                    .foregroundColor(.secondary)

                Text("Tap the antenna icon to start scanning")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            Spacer()
        }
    }
}

// MARK: - Device List View

struct DeviceListView: View {
    let devices: [BlueGateDevice]
    let onOpen: (BlueGateDevice) -> Void
    let onAdmin: (BlueGateDevice) -> Void

    var body: some View {
        List(devices) { device in
            DeviceRow(device: device, onOpen: onOpen, onAdmin: onAdmin)
        }
        .listStyle(.plain)
    }
}

// MARK: - Device Row

struct DeviceRow: View {
    @ObservedObject var device: BlueGateDevice
    let onOpen: (BlueGateDevice) -> Void
    let onAdmin: (BlueGateDevice) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(device.name)
                        .font(.headline)

                    HStack(spacing: 8) {
                        // RSSI indicator
                        HStack(spacing: 2) {
                            Image(systemName: rssiIcon)
                                .foregroundColor(rssiColor)
                            Text("\(device.rssi) dBm")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }

                        // State indicator
                        Text(stateText)
                            .font(.caption)
                            .foregroundColor(stateColor)
                    }
                }

                Spacer()
            }

            // Error message
            if let error = device.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
            }

            // Buttons
            HStack(spacing: 12) {
                Button(action: { onOpen(device) }) {
                    HStack {
                        Image(systemName: "door.garage.open")
                            .font(.title2)
                        Text("Open")
                            .font(.title3)
                            .fontWeight(.semibold)
                    }
                    .frame(maxWidth: .infinity)
                    .frame(height: 60)
                }
                .buttonStyle(.borderedProminent)
                .tint(isRecentlyAuthenticated ? .green : .blue)
                .disabled(device.state == .authenticating || device.state == .connecting)

                // Show Admin button if admin rights were ever detected for this device
                if device.hasAdminRights {
                    Button(action: { onAdmin(device) }) {
                        HStack {
                            Image(systemName: "gearshape")
                                .font(.title2)
                            Text("Admin")
                                .font(.title3)
                                .fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 60)
                    }
                    .buttonStyle(.bordered)
                    .disabled(device.state == .authenticating || device.state == .connecting)
                }
            }
        }
        .padding(.vertical, 8)
        .background(showSuccessHighlight ? Color.green.opacity(0.1) : Color.clear)
        .cornerRadius(8)
    }

    private var rssiIcon: String {
        if device.rssi > -50 { return "wifi" }
        if device.rssi > -70 { return "wifi" }
        return "wifi.exclamationmark"
    }

    private var rssiColor: Color {
        if device.rssi > -50 { return .green }
        if device.rssi > -70 { return .orange }
        return .red
    }

    private var stateText: String {
        switch device.state {
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting..."
        case .connected: return "Connected"
        case .authenticating: return "Authenticating..."
        case .authenticated: return device.isAdmin ? "Authenticated (Admin)" : "Authenticated"
        case .error: return "Error"
        }
    }

    private var stateColor: Color {
        switch device.state {
        case .disconnected: return .secondary
        case .connecting, .authenticating: return .orange
        case .connected: return .blue
        case .authenticated: return .green
        case .error: return .red
        }
    }

    private var showSuccessHighlight: Bool {
        isRecentlyAuthenticated
    }

    private var isRecentlyAuthenticated: Bool {
        if device.state == .authenticated {
            return true
        }
        if let lastAuth = device.lastAuthenticatedAt {
            return Date().timeIntervalSince(lastAuth) < 2.5
        }
        return false
    }
}

#Preview {
    ContentView()
        .environmentObject(KeyManager())
        .environmentObject(BLEManager())
}

// MARK: - BlueGateDevice extension for lastAuthenticatedAt

import Combine
import Foundation

extension BlueGateDevice {
    // Store the last successful authentication time
    private static var _lastAuthenticatedAt = [UUID: Date]()
    var lastAuthenticatedAt: Date? {
        get { Self._lastAuthenticatedAt[id] }
        set {
            Self._lastAuthenticatedAt[id] = newValue
            self.objectWillChange.send()
        }
    }
}
