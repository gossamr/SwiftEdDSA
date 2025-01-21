//
//  TestBlindSign.swift
//  SwiftEdTests
//
//  Created by gossamr on 1/21/25.
//

import XCTest
@testable import SwiftEdDSA

class TestBlindSign: XCTestCase {
    func test1() throws {
        var msg_b = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&msg_b)
        let kind: Ed.Kind = .ed25519

        // Bob starts
        let skBob = PrivateKey(kind: kind)
        let pkBob = PublicKey(privateKey: skBob)
        let k = Ed.randomNonce(kind: kind)
        let Rb: Bytes = BlindSign.scalarToPoint(k)
        let signed = try skBob.sign(message: msg_b)
        XCTAssert(pkBob.verify(signature: signed, message: msg_b))

        // Bob sends Rb to Alice
        let blind = try BlindSign(Pb: pkBob.r, Rb: Rb)
        let e = try blind.transaction(msg: msg_b)

        // Alice sends e to Bob
        let s = try BlindSign.sign(e: e, sk: skBob, k: k)

        // Bob sends s to Alice
        let sig = blind.signature(s: s)

        // Alice sends sig and message to Bob
        XCTAssert(pkBob.verify(signature: sig, message: msg_b))
    }
}
