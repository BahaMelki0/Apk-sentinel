# Proxy Setup

Proxy Lab is a standalone local testing proxy. Use it only for browsers, emulators, devices, accounts, and networks in your authorized test scope.

## Start A Proxy Session

1. Open `http://127.0.0.1:5050/proxy`.
2. Create a session or use the defaults from Settings.
3. Click Start.
4. Configure the test client to use the shown host and port.
5. Turn Intercept On only when you want traffic to pause until you forward or drop it.

## Brave On Windows

Use this flow when testing with Brave on the same workstation:

1. In Proxy Lab, generate the TLS CA.
2. Download `Browser / Brave (.cer)`.
3. Open Windows certificate manager with `certmgr.msc`.
4. Import the `.cer` into `Trusted Root Certification Authorities > Certificates`.
5. Restart Brave.
6. Configure Brave or Windows to use the APK Sentinel proxy, usually `127.0.0.1:<proxy-port>`.
7. Browse an HTTP site first to confirm basic capture.
8. Browse an HTTPS site in scope. If the CA is trusted, Proxy Lab should show decrypted `GET`, `POST`, or other HTTP methods instead of only `CONNECT`.
9. Remove the CA from Trusted Root Certification Authorities when testing is finished.

If you still only see `CONNECT`, the browser is tunneling HTTPS but does not trust the APK Sentinel CA, the proxy session was started before the CA was ready, or the browser is not using the proxy you expect.

## Android Emulator

For Android Studio emulator traffic, point the emulator or app network proxy to:

```text
10.0.2.2:<proxy-port>
```

Install the Android user CA from Proxy Lab for normal user credential testing. Some apps do not trust user-installed CAs on Android 7+ unless their network security config allows it. Rooted emulator/system-store CA workflows can use the Android system `.0` PEM download.

## Physical Device

1. Put the device and workstation on the same network.
2. Use the workstation LAN IP and the Proxy Lab port.
3. Allow the port through the local firewall.
4. Install the Android user CA on the device if HTTPS decryption is required.
5. Remove the CA and proxy settings after testing.

## Manual Smoke Test

1. Start Proxy Lab on `127.0.0.1:8088`.
2. Configure Brave to use `127.0.0.1:8088`.
3. Open Proxy Lab and turn Intercept On.
4. Load an in-scope HTTP URL in Brave.
5. Confirm Brave waits while Proxy Lab shows a paused request.
6. Edit the raw request path or header in the Interceptor editor.
7. Click Forward and confirm the browser loads.
8. Open Repeater from the captured request history.
9. Edit the raw request and send it.
10. Confirm the response panel shows status, headers, and body preview.

## Cleanup

Use Clear History to remove captured proxy requests and replays. Use Delete on a proxy session to stop it, remove its capture log, and clear related saved captures.
