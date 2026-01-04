import SwiftUI

@main
struct BlueGateApp: App {
    @StateObject private var keyManager = KeyManager()
    @StateObject private var bleManager = BLEManager()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(keyManager)
                .environmentObject(bleManager)
        }
    }
}
