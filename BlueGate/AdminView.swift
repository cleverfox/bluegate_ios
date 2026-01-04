import SwiftUI

struct AdminView: View {
    @EnvironmentObject var bleManager: BLEManager
    @ObservedObject var device: BlueGateDevice
    @Environment(\.dismiss) var dismiss

    @State private var selectedTab = 0
    @State private var gateName: String = ""
    @State private var isLoadingName = true

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Tab selector
                Picker("Tab", selection: $selectedTab) {
                    Text("Keys").tag(0)
                    Text("Settings").tag(1)
                }
                .pickerStyle(.segmented)
                .padding()
                .onAppear {
                    print("[AdminView] View appeared for device: \(device.name)")
                }

                // Tab content
                if selectedTab == 0 {
                    KeysTab(device: device, bleManager: bleManager)
                } else {
                    SettingsTab(device: device, bleManager: bleManager, gateName: $gateName)
                }
            }
            .navigationTitle("Admin: \(device.name)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Close") {
                        // Disconnect on close
                        bleManager.disconnect(from: device)
                        dismiss()
                    }
                }
            }
            .onAppear {
                loadGateName()
            }
        }
    }

    private func loadGateName() {
        Task {
            do {
                let name = try await bleManager.getGateName(device: device)
                DispatchQueue.main.async {
                    gateName = name
                    isLoadingName = false
                }
            } catch {
                DispatchQueue.main.async {
                    isLoadingName = false
                }
            }
        }
    }
}

// MARK: - Keys Tab

struct KeysTab: View {
    @ObservedObject var device: BlueGateDevice
    var bleManager: BLEManager

    @State private var keyHex: String = ""
    @State private var isAdmin: Bool = false
    @State private var keys: [StoredKey] = []
    @State private var isLoading = false
    @State private var showingAlert = false
    @State private var alertTitle = ""
    @State private var alertMessage = ""

    struct StoredKey: Identifiable {
        let id: Int
        let data: Data

        var hexString: String {
            data.map { String(format: "%02x", $0) }.joined()
        }

        var isAdmin: Bool {
            guard let firstByte = data.first else { return false }
            return (firstByte & 0x80) != 0
        }

        var keyType: String {
            guard let firstByte = data.first else { return "?" }
            let type = firstByte & 0x03
            switch type {
            case 0x01: return "Ed25519"
            case 0x02, 0x03: return "secp256r1"
            default: return "Unknown"
            }
        }
    }
    
    // Strips all whitespace and newline characters from keyHex
    private var cleanedKeyHex: String {
        keyHex.replacingOccurrences(of: "\\s", with: "", options: .regularExpression)
    }

    var body: some View {
        VStack(spacing: 0) {
            // Add/Delete Key Section
            VStack(spacing: 12) {
                TextField("Public key (33 bytes hex)", text: $keyHex)
                    .font(.system(.body, design: .monospaced))
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                Toggle("Admin", isOn: $isAdmin)

                HStack(spacing: 16) {
                    Button(action: addKey) {
                        HStack {
                            Image(systemName: "plus.circle.fill")
                            Text("Add Key")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(cleanedKeyHex.count != 66 || isLoading)

                    Button(action: deleteKey) {
                        HStack {
                            Image(systemName: "minus.circle.fill")
                            Text("Delete Key")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .tint(.red)
                    .disabled(cleanedKeyHex.count != 66 || isLoading)
                }
            }
            .padding()

            Divider()

            // Load Keys Button
            Button(action: loadKeys) {
                HStack {
                    if isLoading {
                        ProgressView()
                            .scaleEffect(0.8)
                    } else {
                        Image(systemName: "arrow.clockwise")
                    }
                    Text("Load Keys")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .padding(.horizontal)
            .padding(.vertical, 8)
            .disabled(isLoading)

            // Keys Table
            List {
                ForEach(keys) { key in
                    HStack {
                        Text("\(key.id)")
                            .font(.system(.body, design: .monospaced))
                            .frame(width: 30, alignment: .leading)

                        VStack(alignment: .leading, spacing: 2) {
                            Text(key.hexString)
                                .font(.system(.caption, design: .monospaced))
                                .lineLimit(1)

                            HStack(spacing: 8) {
                                Text(key.keyType)
                                    .font(.caption2)
                                    .foregroundColor(.secondary)

                                if key.isAdmin {
                                    Text("Admin")
                                        .font(.caption2)
                                        .foregroundColor(.orange)
                                        .fontWeight(.bold)
                                }
                            }
                        }
                    }
                    .onTapGesture {
                        keyHex = key.hexString
                        isAdmin = key.isAdmin
                    }
                }
            }
            .listStyle(.plain)
        }
        .alert(alertTitle, isPresented: $showingAlert) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(alertMessage)
        }
    }

    private func addKey() {
        // Build the key with admin flag if needed
        var finalKeyHex = cleanedKeyHex
        if isAdmin && cleanedKeyHex.count >= 2 {
            // Get the first byte and set admin bit
            if let firstByte = UInt8(String(cleanedKeyHex.prefix(2)), radix: 16) {
                let newFirstByte = firstByte | 0x80
                finalKeyHex = String(format: "%02x", newFirstByte) + String(cleanedKeyHex.dropFirst(2))
            }
        }

        isLoading = true
        bleManager.addKey(device: device, keyHex: finalKeyHex) { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success:
                    alertTitle = "Success"
                    alertMessage = "Key added successfully"
                    keyHex = ""
                    isAdmin = false
                    loadKeys()
                case .failure(let error):
                    alertTitle = "Error"
                    alertMessage = error.localizedDescription
                }
                showingAlert = true
            }
        }
    }

    private func deleteKey() {
        isLoading = true
        bleManager.deleteKey(device: device, keyHex: cleanedKeyHex) { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success:
                    alertTitle = "Success"
                    alertMessage = "Key deleted successfully"
                    keyHex = ""
                    isAdmin = false
                    loadKeys()
                case .failure(let error):
                    alertTitle = "Error"
                    alertMessage = error.localizedDescription
                }
                showingAlert = true
            }
        }
    }

    private func loadKeys() {
        isLoading = true
        keys = []
        bleManager.getAllKeys(device: device) { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success(let keyDataList):
                    keys = keyDataList.enumerated().map { index, data in
                        StoredKey(id: index, data: data)
                    }
                case .failure(let error):
                    alertTitle = "Error"
                    alertMessage = error.localizedDescription
                    showingAlert = true
                }
            }
        }
    }
}

// MARK: - Settings Tab

struct SettingsTab: View {
    @ObservedObject var device: BlueGateDevice
    var bleManager: BLEManager
    @Binding var gateName: String

    @State private var slotId: String = ""
    @State private var slotValue: String = ""
    @State private var isLoading = false
    @State private var showingAlert = false
    @State private var alertTitle = ""
    @State private var alertMessage = ""

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                // Config Section
                VStack(spacing: 12) {
                    HStack(spacing: 12) {
                        VStack(alignment: .leading) {
                            Text("Slot ID")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            TextField("0-254", text: $slotId)
                                .keyboardType(.numberPad)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                                .frame(width: 80)
                        }

                        VStack(alignment: .leading) {
                            Text("Value")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            TextField("Value", text: $slotValue)
                                .keyboardType(.numberPad)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }
                    }

                    HStack(spacing: 16) {
                        Button(action: setConfig) {
                            HStack {
                                Image(systemName: "square.and.arrow.down")
                                Text("Set Config")
                            }
                            .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(slotId.isEmpty || slotValue.isEmpty || isLoading)

                        Button(action: getConfig) {
                            HStack {
                                Image(systemName: "square.and.arrow.up")
                                Text("Get Config")
                            }
                            .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .disabled(slotId.isEmpty || isLoading)
                    }

                    // Slot reference
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Slots: 0=OpenDuration, 1=CloseDelay, 2=LampDuration, 3=AdvInterval, 4=ObstacleTimeout")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
                .padding()

                Divider()

                // Gate Name Section
                VStack(spacing: 12) {
                    VStack(alignment: .leading) {
                        Text("Gate Name")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        TextField("Gate name", text: $gateName)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                    }

                    Button(action: saveName) {
                        HStack {
                            Image(systemName: "checkmark.circle.fill")
                            Text("Save Name")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(gateName.isEmpty || isLoading)

                    Text("Name change takes effect after device restart")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding()

                if isLoading {
                    ProgressView()
                        .padding()
                }
            }
        }
        .alert(alertTitle, isPresented: $showingAlert) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(alertMessage)
        }
    }

    private func setConfig() {
        guard let slot = UInt8(slotId),
              let value = UInt32(slotValue) else {
            alertTitle = "Error"
            alertMessage = "Invalid slot ID or value"
            showingAlert = true
            return
        }

        isLoading = true
        bleManager.setParameter(device: device, slot: slot, value: value) { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success:
                    alertTitle = "Success"
                    alertMessage = "Config saved"
                case .failure(let error):
                    alertTitle = "Error"
                    alertMessage = error.localizedDescription
                }
                showingAlert = true
            }
        }
    }

    private func getConfig() {
        guard let slot = UInt8(slotId) else {
            alertTitle = "Error"
            alertMessage = "Invalid slot ID"
            showingAlert = true
            return
        }

        isLoading = true
        bleManager.getParameter(device: device, slot: slot) { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success(let value):
                    slotValue = "\(value)"
                case .failure(let error):
                    alertTitle = "Error"
                    alertMessage = error.localizedDescription
                    showingAlert = true
                }
            }
        }
    }

    private func saveName() {
        isLoading = true
        bleManager.setName(device: device, name: gateName) { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success:
                    alertTitle = "Success"
                    alertMessage = "Name saved. Restart device to apply."
                case .failure(let error):
                    alertTitle = "Error"
                    alertMessage = error.localizedDescription
                }
                showingAlert = true
            }
        }
    }
}
