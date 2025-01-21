//
//  TestBlindKey.swift
//  SwiftEdTests
//
//  Created by gossamr on 1/21/25.
//

import XCTest
@testable import SwiftEdDSA

class TestBlindKey: XCTestCase {
//     Test vectors from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-signature-key-blinding-07#name-ed25519-test-vectors
//     Randomly generated private key and blind seed, empty context
//        skS: d142b3b1d532b0a516353a0746a6d43a86cee8efaf6b14ae85c2199072f47d93
//        pkS: cd875d3f46a8e8742cf4a6a9f9645d4153a394a5a0a8028c9041cd455d093cd5
//        bk: bb58c768d9b16571f553efd48207e64391e16439b79fe9409e70b38040c81302
//        pkR: 666443ce8f03fa09240db73a584efad5462ffe346b14fd78fb666b25db29902f
//        message: 68656c6c6f20776f726c64
//        context:
//        signature: 5458111c708ce05cb0a1608b08dc649937dc22cf1da045eb866f2face50be
//        930e79b44d57e5215a82ac227bdccccca52bfe509b96efe8e723cb42b5f14be5f0e
    let t1_skS  = Data(hex: "d142b3b1d532b0a516353a0746a6d43a86cee8efaf6b14ae85c2199072f47d93")!.bytes
    let t1_pkS  = Data(hex: "cd875d3f46a8e8742cf4a6a9f9645d4153a394a5a0a8028c9041cd455d093cd5")!.bytes
    let t1_bk   = Data(hex: "bb58c768d9b16571f553efd48207e64391e16439b79fe9409e70b38040c81302")!.bytes
    let t1_pkR  = Data(hex: "666443ce8f03fa09240db73a584efad5462ffe346b14fd78fb666b25db29902f")!.bytes
    let t1_msg  = Data(hex: "68656c6c6f20776f726c64")!.bytes
    let t1_ctx: Bytes  = []
    let t1_sig  = Data(hex: "5458111c708ce05cb0a1608b08dc649937dc22cf1da045eb866f2face50be930e79b44d57e5215a82ac227bdccccca52bfe509b96efe8e723cb42b5f14be5f0e")!.bytes

//     Randomly generated private key seed and zero blind seed, empty context
//        skS: aa69e9cb50abf39b05ebc823242c4fd13ccadd0dadc1b45f6fcbf7be4f30db5d
//        pkS: 5c9a9e271f204c931646aa079e2e66f0783ab3d29946eff37bd3b569e9c8e009
//        bk: 0000000000000000000000000000000000000000000000000000000000000000
//        pkR: 23eb5eccb9448ee8403c36595ccfd5edd7257ae70da69aa22282a0a7cd97e443
//        message: 68656c6c6f20776f726c64
//        context:
//        signature: 4e9f3ad2b14cf2f9bbf4b88a8832358a568bd69368b471dfabac594e8a8b3
//        3ab54978ecf902560ed754f011186c4c4dda65d158b96c1e6b99a8e150a26e51e03
    let t2_skS  = Data(hex: "aa69e9cb50abf39b05ebc823242c4fd13ccadd0dadc1b45f6fcbf7be4f30db5d")!.bytes
    let t2_pkS  = Data(hex: "5c9a9e271f204c931646aa079e2e66f0783ab3d29946eff37bd3b569e9c8e009")!.bytes
    let t2_bk   = Data(hex: "0000000000000000000000000000000000000000000000000000000000000000")!.bytes
    let t2_pkR  = Data(hex: "23eb5eccb9448ee8403c36595ccfd5edd7257ae70da69aa22282a0a7cd97e443")!.bytes
    let t2_msg  = Data(hex: "68656c6c6f20776f726c64")!.bytes
    let t2_ctx: Bytes  = []
    let t2_sig  = Data(hex: "4e9f3ad2b14cf2f9bbf4b88a8832358a568bd69368b471dfabac594e8a8b33ab54978ecf902560ed754f011186c4c4dda65d158b96c1e6b99a8e150a26e51e03")!.bytes

//     Randomly generated private key and blind seed, non-empty context
//        skS: d1e5a0f806eb3c491566cef6d2d195e6bbf0a54c9de0e291a7ced050c63ea91c
//        pkS: 8b37c949d39cddf4d2a0fc0da781ea7f85c7bfbdfeb94a3c9ecb5e8a3c24d65f
//        bk: 05b235297dff87c492835d562c6e03c0f36b9c306f2dcb3b5038c2744d4e8a70
//        pkR: 019b0a06107e01361facdad39ec16a9647c86c0086bc38825eb664b97d9c514d
//        message: 68656c6c6f20776f726c64
//        context: d6bbaa0646f5617d3cbd1e22ef05e714d1ec7812efff793999667648b2cc54bc
//        signature: f54214acb3c695c46b1e7aa2da947273cb19ec33d8215dde0f43a8f7250fe
//        bb508f4a5007e3c96be6402074ec843d40358a281ff969c66c1724016208650dd09
    let t3_skS  = Data(hex: "d1e5a0f806eb3c491566cef6d2d195e6bbf0a54c9de0e291a7ced050c63ea91c")!.bytes
    let t3_pkS  = Data(hex: "8b37c949d39cddf4d2a0fc0da781ea7f85c7bfbdfeb94a3c9ecb5e8a3c24d65f")!.bytes
    let t3_bk   = Data(hex: "05b235297dff87c492835d562c6e03c0f36b9c306f2dcb3b5038c2744d4e8a70")!.bytes
    let t3_pkR  = Data(hex: "019b0a06107e01361facdad39ec16a9647c86c0086bc38825eb664b97d9c514d")!.bytes
    let t3_msg  = Data(hex: "68656c6c6f20776f726c64")!.bytes
    let t3_ctx  = Data(hex: "d6bbaa0646f5617d3cbd1e22ef05e714d1ec7812efff793999667648b2cc54bc")!.bytes
    let t3_sig  = Data(hex: "f54214acb3c695c46b1e7aa2da947273cb19ec33d8215dde0f43a8f7250febb508f4a5007e3c96be6402074ec843d40358a281ff969c66c1724016208650dd09")!.bytes

//    Randomly generated private key seed and zero blind seed, non-empty context
//        skS: 89e3e3acef6a6c2d9b7c062199bf996f9ae96b662c73e2b445636f9f22d5012e
//        pkS: 3f667a2305a8baf328a1d8e9ed726f278229607d28fb32d9933da7379947ac44
//        bk: 0000000000000000000000000000000000000000000000000000000000000000
//        pkR: 90a543dd29c6e6cd08ef85c43618f2d314139db5baed802383cf674310294e40
//        message: 68656c6c6f20776f726c64
//        context: 802def4d21c7c7d0fa4b48af5e85f8ebfc4119a04117c14d961567eaef2859f2
//        signature: ce305a0f40a3270a84d2d9403617cdb89b7b4edf779b4de27f9acaadf1716
//        84b162e752c95f17b16aaca7c2662e69ba9696bdd230a107ecab973886e8d5bf00e
    let t4_skS  = Data(hex: "89e3e3acef6a6c2d9b7c062199bf996f9ae96b662c73e2b445636f9f22d5012e")!.bytes
    let t4_pkS  = Data(hex: "3f667a2305a8baf328a1d8e9ed726f278229607d28fb32d9933da7379947ac44")!.bytes
    let t4_bk   = Data(hex: "0000000000000000000000000000000000000000000000000000000000000000")!.bytes
    let t4_pkR  = Data(hex: "90a543dd29c6e6cd08ef85c43618f2d314139db5baed802383cf674310294e40")!.bytes
    let t4_msg  = Data(hex: "68656c6c6f20776f726c64")!.bytes
    let t4_ctx  = Data(hex: "802def4d21c7c7d0fa4b48af5e85f8ebfc4119a04117c14d961567eaef2859f2")!.bytes
    let t4_sig  = Data(hex: "ce305a0f40a3270a84d2d9403617cdb89b7b4edf779b4de27f9acaadf171684b162e752c95f17b16aaca7c2662e69ba9696bdd230a107ecab973886e8d5bf00e")!.bytes

    func blindkey_test(skS: Bytes, pkS: Bytes, pkR: Bytes, bk: Bytes, msg: Bytes, ctx: Bytes, sig: Bytes) throws {
        let blind = BlindKey(sk: try PrivateKey(s: skS), bk: bk, ctx: ctx)
        let pkR2 = try blind.blindPubKey()
        XCTAssert(pkR == pkR2)
        let pkS2 = try blind.unblindPubKey(pkR: pkR2)
        XCTAssert(pkS == pkS2)
        let sig2 = try blind.blindKeySign(msg: msg)
        XCTAssert(sig == sig2)
        let pk = try PublicKey(r: pkR)
        XCTAssert(pk.verify(signature: sig, message: msg))
    }

    func test1() throws {
        try blindkey_test(skS: t1_skS, pkS: t1_pkS, pkR: t1_pkR, bk: t1_bk, msg: t1_msg, ctx: t1_ctx, sig: t1_sig)
        try blindkey_test(skS: t2_skS, pkS: t2_pkS, pkR: t2_pkR, bk: t2_bk, msg: t2_msg, ctx: t2_ctx, sig: t2_sig)
        try blindkey_test(skS: t3_skS, pkS: t3_pkS, pkR: t3_pkR, bk: t3_bk, msg: t3_msg, ctx: t3_ctx, sig: t3_sig)
        try blindkey_test(skS: t4_skS, pkS: t4_pkS, pkR: t4_pkR, bk: t4_bk, msg: t4_msg, ctx: t4_ctx, sig: t4_sig)
    }

    func test2() throws {
        // Test random keys, empty context
        let msg = "test message".data(using: .utf8)!.bytes
        let sk = PrivateKey(kind: .ed25519)
        let pk = PublicKey(privateKey: sk)
        var bk = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&bk)

        let ctx: Bytes = []
        let blind = BlindKey(sk: sk, bk: bk, ctx: ctx)
        let pkR = try blind.blindPubKey()
        XCTAssertFalse(pkR == pk.r)
        let pkS = try blind.unblindPubKey(pkR: pkR)
        XCTAssert(pkS == pk.r)

        let sig = try blind.blindKeySign(msg: msg)
        let vk = try PublicKey(r: pkR)
        XCTAssert(vk.verify(signature: sig, message: msg))
        XCTAssertFalse(vk.verify(signature: sig, message: msg + [1]))
    }
    
    func test3() throws {
        // Test random keys, random context
        let msg = "test message".data(using: .utf8)!.bytes
        let sk = PrivateKey(kind: .ed25519)
        let pk = PublicKey(privateKey: sk)
        var bk = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&bk)

        var ctx = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&ctx)

        let blind = BlindKey(sk: sk, bk: bk, ctx: ctx)
        let pkR = try blind.blindPubKey()
        XCTAssertFalse(pkR == pk.r)
        let pkS = try blind.unblindPubKey(pkR: pkR)
        XCTAssert(pkS == pk.r)

        let sig = try blind.blindKeySign(msg: msg)
        let vk = try PublicKey(r: pkR)
        XCTAssert(vk.verify(signature: sig, message: msg))
        XCTAssertFalse(vk.verify(signature: sig, message: msg + [1]))
    }
    
    func test4() throws {
        // Test random message, random keys, empty context
        var msg = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&msg)

        let sk = PrivateKey(kind: .ed25519)
        let pk = PublicKey(privateKey: sk)
        var bk = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&bk)

        let ctx: Bytes = []
        let blind = BlindKey(sk: sk, bk: bk, ctx: ctx)
        let pkR = try blind.blindPubKey()
        XCTAssertFalse(pkR == pk.r)
        let pkS = try blind.unblindPubKey(pkR: pkR)
        XCTAssert(pkS == pk.r)

        let sig = try blind.blindKeySign(msg: msg)
        let vk = try PublicKey(r: pkR)
        XCTAssert(vk.verify(signature: sig, message: msg))
        XCTAssertFalse(vk.verify(signature: sig, message: msg + [1]))
    }
    
    func test5() throws {
        // Test random message, random keys, random context
        var msg = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&msg)

        let sk = PrivateKey(kind: .ed25519)
        let pk = PublicKey(privateKey: sk)
        var bk = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&bk)

        var ctx = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&ctx)

        let blind = BlindKey(sk: sk, bk: bk, ctx: ctx)
        let pkR = try blind.blindPubKey()
        XCTAssertFalse(pkR == pk.r)
        let pkS = try blind.unblindPubKey(pkR: pkR)
        XCTAssert(pkS == pk.r)

        let sig = try blind.blindKeySign(msg: msg)
        let vk = try PublicKey(r: pkR)
        XCTAssert(vk.verify(signature: sig, message: msg))
        XCTAssertFalse(vk.verify(signature: sig, message: msg + [1]))
    }
    
    func test6() throws {
        // Test async key blinding and signing
        var msg = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&msg)

        let sk = PrivateKey(kind: .ed25519)
        let pk = PublicKey(privateKey: sk)
        var bk = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&bk)

        var ctx = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&ctx)

        let blind = BlindKey(pk: pk, bk: bk, ctx: ctx)
        let pkR = try blind.blindPubKey()
        XCTAssertFalse(pkR == pk.r)
        let pkS = try blind.unblindPubKey(pkR: pkR)
        XCTAssert(pkS == pk.r)

        // Can't sign with a public-only BlindKey instance
        XCTAssertThrowsError(try blind.blindKeySign(msg: msg))

        let blind2 = BlindKey(sk: sk, bk: bk, ctx: ctx)
        let sig = try blind2.blindKeySign(msg: msg)

        let vk = try PublicKey(r: pkR)
        XCTAssert(vk.verify(signature: sig, message: msg))
        XCTAssertFalse(vk.verify(signature: sig, message: msg + [1]))
    }
    
    func test7() throws {
        // Test async key blinding, key unblinding, and signing
        var msg = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&msg)

        let sk = PrivateKey(kind: .ed25519)
        let pk = PublicKey(privateKey: sk)
        var bk = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&bk)

        var ctx = Bytes(repeating: 0, count: 32)
        Ed.randomBytes(&ctx)

        let blind = BlindKey(pk: pk, bk: bk, ctx: ctx)
        let pkR = try blind.blindPubKey()
        XCTAssertFalse(pkR == pk.r)

        let blind2 = BlindKey(bk: bk, ctx: ctx)

        // Can't blind with a keyless BlindKey instance
        XCTAssertThrowsError(try blind2.blindPubKey())

        let pkS = try blind2.unblindPubKey(pkR: pkR)
        XCTAssert(pkS == pk.r)

        // Can't sign with a public-only BlindKey instance
        XCTAssertThrowsError(try blind.blindKeySign(msg: msg))

        let blind3 = BlindKey(sk: sk, bk: bk, ctx: ctx)
        let sig = try blind3.blindKeySign(msg: msg)

        let vk = try PublicKey(r: pkR)
        XCTAssert(vk.verify(signature: sig, message: msg))
        XCTAssertFalse(vk.verify(signature: sig, message: msg + [1]))
    }
}
