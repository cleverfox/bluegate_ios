# BlueGate iOS App

BlueGate is an iOS app for controlling and administering BlueGate BLE gate controllers. It can scan for nearby devices, authenticate, open/close the gate, and manage settings and keys from the admin interface.

## What it does
- Scan and connect to BlueGate devices over BLE
- Authenticate using the device's public key flow
- Open/close the gate and keep it open in manual mode
- Admin tools for managing keys and configuration

## Build and run
1) Open `BlueGate.xcodeproj` in Xcode.
2) Select the `BlueGate` scheme and a target device or simulator.
3) Build and run.

Notes:
- BLE features require a real iOS device.
- Make sure Bluetooth permissions are granted when prompted.
