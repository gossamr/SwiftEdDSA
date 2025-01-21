//
//  BlindKey.swift
//  SwiftEd
//
//  Created by gossamr on 1/20/25.
//

import Foundation
import BigInt
import Digest

public class BlindKey {
    let sk: PrivateKey?
    let pk: PublicKey?
    let bk: Bytes
    let ctx: Bytes
    let blindCtx: Bytes
    let b: Bytes
    let r: BInt
    let prefix2: Bytes

    /// Suitable only for key blinding and unblinding
    public init(pk: PublicKey, bk: Bytes, ctx: Bytes) {
        self.sk = nil
        self.pk = pk
        self.bk = bk
        self.ctx = ctx
        self.blindCtx = bk + [0x00] + ctx
        let md = MessageDigest(.SHA2_512)
        md.update(self.blindCtx)
        self.b = md.digest()
        self.r = Ed25519.reduceModL(Ed.toBInt(Bytes(b[0 ..< 32])))
        self.prefix2 = Array(self.b[32 ..< 64])
    }

    /// Suitable for unblinding only
    public init(bk: Bytes, ctx: Bytes) {
        self.sk = nil
        self.pk = nil
        self.bk = bk
        self.ctx = ctx
        self.blindCtx = bk + [0x00] + ctx
        let md = MessageDigest(.SHA2_512)
        md.update(self.blindCtx)
        self.b = md.digest()
        self.r = Ed25519.reduceModL(Ed.toBInt(Bytes(b[0 ..< 32])))
        self.prefix2 = Array(self.b[32 ..< 64])
    }

    /// Suitable for blind signing
    public init(sk: PrivateKey, bk: Bytes, ctx: Bytes) {
        self.sk = sk
        self.pk = PublicKey(privateKey: sk)
        self.bk = bk
        self.ctx = ctx
        self.blindCtx = bk + [0x00] + ctx
        let md = MessageDigest(.SHA2_512)
        md.update(self.blindCtx)
        self.b = md.digest()
        self.r = Ed25519.reduceModL(Ed.toBInt(Bytes(b[0 ..< 32])))
        self.prefix2 = Array(self.b[32 ..< 64])
    }

    public func blindPubKey() throws -> Bytes {
        guard let pk else { throw Ed.Ex.publicKeyMissing }
        let P = pk.points25519[0] // if pk is PublicKey
//        let P = try Ed25519.decode(self.pk) // if pk is Bytes
        let pkR = P.multiply(self.r).encode()
        // return try PublicKey(r: pkR) // if func returns PublicKey
        return pkR
    }

    public func unblindPubKey(pkR: Bytes) throws -> Bytes {
        let rInv = Ed.toBInt(Array(self.b[0 ..< 32])).modInverse(Ed25519.L)
//        let P = pkR.points25519[0] // if pkR is PublicKey
        let P = try Ed25519.decode(pkR)
        let pkS = P.multiply(rInv).encode()
        // return try PublicKey(r: pkS) // if func returns PublicKey
        return pkS
    }

    public func blindKeySign(msg: Bytes) throws -> Bytes {
        guard let sk else { throw Ed.Ex.privateKeyMissing }
        let md = MessageDigest(.SHA2_512)
        md.update(sk.s)

        // prune the buffer RFC8023:5.1.5
        let h = md.digest()
        var h0 = Bytes(h[0 ..< 32])
        h0[0] &= 0xf8
        h0[31] &= 0x7f
        h0[31] |= 0x40
        let k = Ed25519.reduceModL(Ed.toBInt(Bytes(h0)))

        let prefix1 = h[32 ..< 64]
        let prefix = Array(prefix1 + prefix2)

        let s = Ed25519.reduceModL(k * self.r)
        let pkR = try self.blindPubKey()

        // continue signature process as normal
        return sign(pkR: pkR, msg: msg, prefix: prefix, s: s)
    }

    func sign(pkR: Bytes, msg: Bytes, prefix: Bytes, s: BInt) -> Bytes {
        let md = MessageDigest(.SHA2_512)
        md.update(prefix)
        md.update(msg)
        let r = Ed25519.reduceModL(Ed.toBInt(md.digest()))
        let R = Point25519.multiplyG(Ed25519.toBytes(r)).encode()
        md.update(R)
        md.update(pkR)
        md.update(msg)
        let k = Ed25519.reduceModL(Ed.toBInt(md.digest()))
        let ksr = Ed25519.reduceModL(k * s + r)
        return R + Ed25519.toBytes(ksr)
    }
}
