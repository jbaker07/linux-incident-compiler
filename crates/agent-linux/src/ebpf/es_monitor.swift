//
//  es_monitor.swift
//  Hardened macOS EndpointSecurity Agent
//

import Foundation
import EndpointSecurity

let socketPath = "/tmp/edr_ipc.sock"

guard let client = try? ESClient(subscriptions: [
    .exec, .fork, .exit, .open, .rename,
    .unlink, .mount, .setuid, .authOpen,
    .socketConnect
]) else {
    fatalError("❌ Unable to initialize ESClient.")
}

func writeToSocket(_ payload: [String: Any]) {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return }

    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutablePointer(to: &address.sun_path) {
        $0.withMemoryRebound(to: CChar.self, capacity: 104) {
            _ = strncpy($0, socketPath, 104)
        }
    }

    let size = socklen_t(MemoryLayout<sockaddr_un>.stride)
    let connectResult = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, size)
        }
    }

    guard connectResult >= 0 else {
        close(fd)
        return
    }

    if let json = try? JSONSerialization.data(withJSONObject: payload, options: []) {
        _ = json.withUnsafeBytes { write(fd, $0.baseAddress!, $0.count) }
    }

    close(fd)
}

client.setEventHandler { event in
    var payload: [String: Any] = [
        "timestamp": Date().timeIntervalSince1970,
        "es_source": "macOS",
        "event_type": event.eventType.rawValue
    ]

    switch event.eventType {
    case .exec:
        if let e = event.exec {
            payload["pid"] = e.process.pid
            payload["ppid"] = e.process.ppid
            payload["path"] = e.process.executable.path
            payload["args"] = e.arguments.map { $0.value }
            payload["uid"] = e.process.uid
            payload["session"] = e.process.sessionID
        }

    case .fork:
        if let e = event.fork {
            payload["parent_pid"] = e.parent.pid
            payload["child_pid"] = e.child.pid
        }

    case .exit:
        if let e = event.exit {
            payload["pid"] = e.process.pid
            payload["status"] = e.stat
        }

    case .open:
        if let e = event.open {
            payload["pid"] = e.process.pid
            payload["file"] = e.file.path
        }

    case .rename:
        if let e = event.rename {
            payload["pid"] = e.process.pid
            payload["src"] = e.source.path
            payload["dst"] = e.destinationNewPath
        }

    case .unlink:
        if let e = event.unlink {
            payload["pid"] = e.process.pid
            payload["file"] = e.target.path
        }

    case .mount:
        if let e = event.mount {
            payload["pid"] = e.process.pid
            payload["dev"] = e.mount.devName
        }

    case .setuid:
        if let e = event.setuid {
            payload["pid"] = e.process.pid
            payload["uid"] = e.uid
        }

    case .authOpen:
        if let e = event.authOpen {
            payload["pid"] = e.process.pid
            payload["tty"] = e.ttyDevicePath
        }

    case .socketConnect:
        if let e = event.socketConnect {
            payload["pid"] = e.process.pid
            payload["addr"] = e.remoteAddress
        }

    default:
        return
    }

    writeToSocket(payload)
}

client.run()
print("🚀 macOS EndpointSecurity agent started ✅")
