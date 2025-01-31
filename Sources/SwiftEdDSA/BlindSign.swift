//
//  BlindSign.swift
//  SwiftEd
//
//  Created by gossamr on 1/19/25.
//

import Foundation
import BigInt
import Digest

public class BlindSign {
    let a: BInt
    let b: BInt
    let P: Point25519
    let R: Point25519

    public init(Pb: Bytes, Rb: Bytes, a: BInt? = nil, b: BInt? = nil) throws {
        self.a = a != nil ? a! : Ed.randomNonce(kind: .ed25519)
        self.b = b != nil ? b! : Ed.randomNonce(kind: .ed25519)
        self.P = try Ed25519.decode(Pb)
        let aG: Point25519 = BlindSign.scalarToPoint(self.a)
        let RaG = try Ed25519.decode(Rb).add(aG)
        let bP = self.P.multiply(self.b)
        self.R = RaG.add(bP)
    }

    static func scalarToPoint(_ s: BInt) -> Point25519 {
        return Point25519.multiplyG(Ed25519.toBytes(s))
    }

    public static func scalarToPoint(_ s: BInt) -> Bytes {
        return scalarToPoint(s).encode()
    }

    public func getA() -> Bytes {
        return Ed25519.toBytes(self.a)
    }

    public func getB() -> Bytes {
        return Ed25519.toBytes(self.b)
    }

    public func transaction(msg: Bytes) throws -> Bytes {
        let md = MessageDigest(.SHA2_512)
        md.update(self.R.encode())
        md.update(self.P.encode())
        md.update(msg)
        let hash = md.digest()
        let e_ = Ed25519.reduceModL(Ed.toBInt(hash))
        let e = Ed25519.reduceModL(e_ + b)
        return Ed25519.toBytes(e)
    }

    public static func sign(e: Bytes, sk: PrivateKey, k: BInt) throws -> BInt {
        let x: Bytes = sk.asX25519() // buffer pruning
        return Ed25519.reduceModL(Ed.toBInt(e) * Ed.toBInt(x) + k)
    }

    public func signature(s: BInt) -> Bytes {
        return self.R.encode() + Ed25519.toBytes(Ed25519.reduceModL(s + self.a))
    }
}

extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else {
            return nil
        }

        let chars = hex.map { $0 }
        let bytes = stride(from: 0, to: chars.count, by: 2)
            .map { String(chars[$0]) + String(chars[$0 + 1]) }
            .compactMap { UInt8($0, radix: 16) }

        guard hex.count / bytes.count == 2 else { return nil }
        self.init(bytes)
    }

    func hexEncodedString() -> String {
        return map { String(format: "%02.2hhx", $0) }.joined()
    }

    var bytes: Bytes {
        return self.map { UInt8($0) }
    }
}
