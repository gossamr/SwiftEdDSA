//
//  File.swift
//  
//
//  Created by Leif Ibsen on 08/09/2023.
//

import Foundation
import BigInt
import ASN1
import Digest

public class PrivateKey: CustomStringConvertible, Codable {

    // MARK: Stored Properties
    
    /// The private key value - 32 bytes for Ed25519, 57 bytes for Ed448
    public let s: Bytes
    /// The curve OID
    public let oid: ASN1ObjectIdentifier


    // MARK: Computed Properties

    /// The ASN1 encoding of `self`
    public var asn1: ASN1 { get { return ASN1Sequence().add(ASN1Integer(BInt.ZERO)).add(ASN1Sequence().add(self.oid)).add(ASN1OctetString(ASN1OctetString(self.s).encode())) } }
    /// The DER encoding of `self.asn1`
    public var der: Bytes { get { return self.asn1.encode() } }
    /// The PEM encoding of `self.asn1`
    public var pem: String { get { return Base64.pemEncode(self.asn1.encode(), "PRIVATE KEY") } }
    /// A textual representation of the ASN1 encoding of `self`
    public var description: String { get { return self.asn1.description } }

    
    // MARK: Constructors

    /// Creates a new private key of the specified kind
    ///
    /// - Parameters:
    ///   - kind: The private key kind - Ed25519 or Ed448
    public init(kind: Ed.Kind) {
        var n: Int
        switch kind {
        case .ed25519:
            n = 32
            self.oid = Ed.OID25519
        case .ed448:
            n = 57
            self.oid = Ed.OID448
        }
        var x = Bytes(repeating: 0, count: n)
        let ok = SecRandomCopyBytes(kSecRandomDefault, n, &x)
        assert(ok == errSecSuccess, "Random bytes")
        self.s = x
    }

    /// Creates a private key from its value
    ///
    /// - Parameters:
    ///   - s: The private key value, 32 bytes for Ed25519 - 57 bytes for Ed448
    /// - Throws: An exception if the key size is wrong
    public init(s: Bytes) throws {
        self.s = s
        if s.count == 32 {
            self.oid = Ed.OID25519
        } else if s.count == 57 {
            self.oid = Ed.OID448
        } else {
            throw Ed.Ex.keySize
        }
    }

    /// Creates a private key from its DER encoding
    ///
    /// - Parameters:
    ///   - der: The private key DER encoding
    /// - Throws: An exception if the DER encoding is wrong
    public convenience init(der: Bytes) throws {
        let asn1 = try ASN1.build(der)
        guard let seq = asn1 as? ASN1Sequence else {
            throw Ed.Ex.asn1Structure
        }
        if seq.getValue().count < 3 {
            throw Ed.Ex.asn1Structure
        }
        guard let int = seq.get(0) as? ASN1Integer else {
            throw Ed.Ex.asn1Structure
        }
        if int != ASN1.ZERO {
            throw Ed.Ex.asn1Structure
        }
        guard let seq1 = seq.get(1) as? ASN1Sequence else {
            throw Ed.Ex.asn1Structure
        }
        guard let octets = seq.get(2) as? ASN1OctetString else {
            throw Ed.Ex.asn1Structure
        }
        if seq1.getValue().count < 1 {
            throw Ed.Ex.asn1Structure
        }
        guard let oid = seq1.get(0) as? ASN1ObjectIdentifier else {
            throw Ed.Ex.asn1Structure
        }
        guard let seq2 = try ASN1.build(octets.value) as? ASN1OctetString else {
            throw Ed.Ex.asn1Structure
        }
        if (oid == Ed.OID25519 && seq2.value.count == 32) || (oid == Ed.OID448 && seq2.value.count == 57) {
            try self.init(s: seq2.value)
        } else {
            throw Ed.Ex.asn1Structure
        }
    }

    /// Creates a private key from its PEM encoding
    ///
    /// - Parameters:
    ///   - pem: The private key PEM encoding
    /// - Throws: An exception if the PEM encoding is wrong
    public convenience init(pem: String) throws {
        guard let der = Base64.pemDecode(pem, "PRIVATE KEY") else {
            throw Ed.Ex.pemStructure
        }
        try self.init(der: der)
    }

    // MARK: Instance Methods

    /// Signs a message
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - context: The context - the default value is an empty array
    ///   - deterministic: If `true` generate a deterministic signature, else generate a non-deterministic signature - `true` is default
    /// - Returns: The EdDSA signature - 64 bytes for Ed25519, 114 bytes for Ed448
    /// - Throws: A `context` exception if `context` contains more than 255 bytes
    public func sign(message: Bytes, context: Bytes = [], deterministic: Bool = true) throws -> Bytes {
        if context.count > 255 {
            throw Ed.Ex.context
        }
        if self.oid == Ed.OID25519 {
            let md = MessageDigest(.SHA2_512)
            md.update(self.s)
            let h = md.digest()
            var h0 = Bytes(h[0 ..< 32])
            h0[0] &= 0xf8
            h0[31] &= 0x7f
            h0[31] |= 0x40
            let h1 = Bytes(h[32 ..< 64])
            if deterministic {
                if context.count > 0 {
                    md.update(Ed25519.dom2Bytes(context))
                }
                md.update(h1)
                md.update(message)
            } else {
                var z = Bytes(repeating: 0, count: 32)
                Ed.randomBytes(&z)
                if context.count > 0 {
                    md.update(Ed25519.dom2Bytes(context))
                }
                md.update(z)
                md.update(h1)
                md.update(Bytes(repeating: 0, count: 64))
                md.update(message)
            }
            let r = Ed25519.reduceModL(Ed.toBInt(md.digest()))
            let R = Point25519.multiplyG(Ed25519.toBytes(r)).encode()
            let a = Ed.toBInt(h0)
            let A = Point25519.multiplyG(h0).encode()
            if context.count > 0 {
                md.update(Ed25519.dom2Bytes(context))
            }
            md.update(R)
            md.update(A)
            md.update(message)
            let k = Ed25519.reduceModL(Ed.toBInt(md.digest()))
            return R + Ed25519.toBytes(Ed25519.reduceModL(k * a + r))
        } else {
            let shake = SHAKE(.SHAKE256)
            shake.update(self.s)
            let h = shake.digest(114)
            var h0 = Bytes(h[0 ..< 57])
            h0[0] &= 0xfc
            h0[55] |= 0x80
            h0[56] = 0x00
            let h1 = Bytes(h[57 ..< 114])
            if deterministic {
                shake.update(Ed448.dom4Bytes(context))
                shake.update(h1)
                shake.update(message)
            } else {
                var z = Bytes(repeating: 0, count: 57)
                Ed.randomBytes(&z)
                var zeroCount = 408 - context.count - 124
                if zeroCount >= 136 {
                    zeroCount -= 136
                }
                if zeroCount >= 136 {
                    zeroCount -= 136
                }
                shake.update(Ed448.dom4Bytes(context))
                shake.update(z)
                shake.update(h1)
                shake.update(Bytes(repeating: 0, count: zeroCount))
                shake.update(message)
            }
            let r = Ed448.reduceModL(Ed.toBInt(shake.digest(114)))
            let R = Point448.multiplyG(Ed448.toBytes(r)).encode()
            let a = Ed.toBInt(h0)
            let A = Point448.multiplyG(h0).encode()
            shake.update(Ed448.dom4Bytes(context))
            shake.update(R)
            shake.update(A)
            shake.update(message)
            let k = Ed448.reduceModL(Ed.toBInt(shake.digest(114)))
            return R + Ed448.toBytes(Ed448.reduceModL(k * a + r))
        }
    }

    /// Curve conversion is just buffer pruning
    public func asX25519() -> Bytes {
        let md = MessageDigest(.SHA2_512)
        md.update(self.s)
        let h = md.digest()
        var h0 = Bytes(h[0 ..< 32])
        h0[0] &= 0xf8
        h0[31] &= 0x7f
        h0[31] |= 0x40
        return h0
    }

    enum CodingKeys: CodingKey {
        case key
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.s, forKey: .key)
    }

    required public convenience init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let pubKeyRaw = try container.decode(Bytes.self, forKey: .key)
        try self.init(s: pubKeyRaw)
    }
}
