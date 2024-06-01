//
//  Tweetnacl.swift
//  TweetnaclSwift
//
//  Created by Anh Nguyen on 12/9/16.
//  Copyright © 2016 Bitmark. All rights reserved.
//

import Foundation
import CTweetNacl

// MARK: - Utilities

public struct NaclUtil {
    
    public enum NaclUtilError: Error {
        case badKeySize
        case badNonceSize
        case badPublicKeySize
        case badSecretKeySize
        case internalError
    }
    
    static func checkLengths(key: Data, nonce: Data) throws {
        if key.count != Constants.Secretbox.keyBytes {
            throw NaclUtilError.badKeySize
        }
        
        if nonce.count != Constants.Secretbox.nonceBytes {
            throw NaclUtilError.badNonceSize
        }
    }
    
    static func checkBoxLength(publicKey: Data, secretKey: Data) throws {
        if publicKey.count != Constants.Box.publicKeyBytes {
            throw NaclUtilError.badPublicKeySize
        }
        
        if secretKey.count != Constants.Box.secretKeyBytes{
            throw NaclUtilError.badSecretKeySize
        }
    }
    
    public static func secureRandomData(count: Int) throws -> Data {
        // Generation method is platform dependent
        // (The Security framework is only available on Apple platforms).
        #if os(Linux)

        var bytes = [UInt8]()
        for _ in 0..<count {
            let randomByte = UInt8.random(in: UInt8.min...UInt8.max)
            bytes.append(randomByte)
        }
        let randomData = Data(bytes: &bytes, count: count)

        return randomData

        #else

        var randomData = Data(count: count)

        let result = randomData.withUnsafeMutableBytes { (pointer: UnsafeMutableRawBufferPointer) in
            return SecRandomCopyBytes(kSecRandomDefault, count, pointer.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw NaclUtilError.internalError
        }

        return randomData

        #endif
    }
    
    public static func hash(message: Data) throws -> Data {
        var hash = Data(count: Constants.Hash.bytes)
        let r = hash.withUnsafeMutableBytes { (hashPointer: UnsafeMutableRawBufferPointer) -> Int32 in
            return message.withUnsafeBytes { (messagePointer: UnsafeRawBufferPointer) -> Int32 in
                return CTweetNacl.crypto_hash_sha512_tweet(
                    hashPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    messagePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    UInt64(message.count)
                )
            }
        }
        
        if r != 0 {
            throw NaclUtilError.internalError
        }
        
        return hash
    }
    
    public static func verify(x: Data, y: Data) throws -> Bool {
        if x.count == 0 || y.count == 0 {
            throw NaclUtilError.badKeySize
        }
        
        if x.count != y.count {
            throw NaclUtilError.badKeySize
        }
        
        let r = x.withUnsafeBytes { (xPointer: UnsafeRawBufferPointer) -> Int32 in
            return y.withUnsafeBytes { (yPointer: UnsafeRawBufferPointer) -> Int32 in
                return CTweetNacl.crypto_verify_32_tweet(
                    xPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    yPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        
        return r == 0
    }
}

// MARK: - Internal wrapper

struct NaclWrapper {
    enum NaclWrapperError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    static func crypto_box_keypair(secretKey sk: Data) throws -> (publicKey: Data, secretKey: Data) {
        var pk = Data(count: Constants.Box.secretKeyBytes)
        
        let result = pk.withUnsafeMutableBytes { (pkPointer: UnsafeMutableRawBufferPointer) -> Int32 in
            return sk.withUnsafeBytes { (skPointer: UnsafeRawBufferPointer) -> Int32 in
                return CTweetNacl.crypto_scalarmult_curve25519_tweet_base(
                    pkPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    skPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        
        if result != 0 {
            throw NaclWrapperError.internalError
        }
        
        return (pk, sk)
    }
    
    static func crypto_sign_keypair() throws -> (publicKey: Data, secretKey: Data) {
        let sk = try NaclUtil.secureRandomData(count: Constants.Sign.secretKeyBytes)
        
        return try crypto_sign_keypair_seeded(secretKey: sk)
    }
    
    static func crypto_sign_keypair_seeded(secretKey: Data) throws -> (publicKey: Data, secretKey: Data) {
        var pk = Data(count: Constants.Sign.publicKeyBytes)
        var sk = Data(count: Constants.Sign.secretKeyBytes)
        sk.replaceSubrange(0..<Constants.Sign.publicKeyBytes, with: secretKey.subdata(in: 0..<Constants.Sign.publicKeyBytes))
        
        let result = pk.withUnsafeMutableBytes { (pkPointer: UnsafeMutableRawBufferPointer) -> Int32 in
            return sk.withUnsafeMutableBytes { (skPointer: UnsafeMutableRawBufferPointer) -> Int32 in
                return CTweetNacl.crypto_sign_ed25519_tweet_keypair(
                    pkPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    skPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        
        if result != 0 {
            throw NaclWrapperError.internalError
        }
        
        return (pk, sk)
    }
}

// MARK: - Secret-key authenticated encryption

public struct NaclSecretBox {
    public enum NaclSecretBoxError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    public static func secretBox(message: Data, nonce: Data, key: Data) throws -> Data {
        try NaclUtil.checkLengths(key: key, nonce: nonce)
        
        var m = Data(count: Constants.Secretbox.zeroBytes + message.count)
        m.replaceSubrange(Constants.Secretbox.zeroBytes..<m.count, with: message)
        
        var c = Data(count: m.count)
        
        let result = c.withUnsafeMutableBytes { (cPointer: UnsafeMutableRawBufferPointer) -> Int32 in
            return m.withUnsafeBytes { (mPointer: UnsafeRawBufferPointer) -> Int32 in
                return nonce.withUnsafeBytes { (noncePointer: UnsafeRawBufferPointer) -> Int32 in
                    return key.withUnsafeBytes { (keyPointer: UnsafeRawBufferPointer) -> Int32 in
                        return CTweetNacl.crypto_secretbox_xsalsa20poly1305_tweet(
                            cPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            mPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            UInt64(m.count),
                            noncePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            keyPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
        }
        
        if result != 0 {
            throw NaclSecretBoxError.internalError
        }
        return c.subdata(in: Constants.Secretbox.boxZeroBytes..<c.count)
    }
    
    public static func open(box: Data, nonce: Data, key: Data) throws -> Data {
        try NaclUtil.checkLengths(key: key, nonce: nonce)
        
        // Fill data
        var c = Data(count: Constants.Secretbox.boxZeroBytes + box.count)
        c.replaceSubrange(Constants.Secretbox.boxZeroBytes..<c.count, with: box)
        
        var m = Data(count: c.count)
        
        let result = m.withUnsafeMutableBytes { (mPointer: UnsafeMutableRawBufferPointer) -> Int32 in
            return c.withUnsafeBytes { (cPointer: UnsafeRawBufferPointer) -> Int32 in
                return nonce.withUnsafeBytes { (noncePointer: UnsafeRawBufferPointer) -> Int32 in
                    return key.withUnsafeBytes { (keyPointer: UnsafeRawBufferPointer) -> Int32 in
                        return CTweetNacl.crypto_secretbox_xsalsa20poly1305_tweet_open(
                            mPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            cPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            UInt64(c.count),
                            noncePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            keyPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
        }
        
        if result != 0 {
            throw NaclSecretBoxError.creationFailed
        }
        
        return m.subdata(in: Constants.Secretbox.zeroBytes..<c.count)
    }
}

// MARK: - Scalar multiplication

public struct NaclScalarMult {
    public enum NaclScalarMultError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    public static func scalarMult(n: Data, p: Data) throws -> Data {
        if n.count != Constants.Scalarmult.scalarBytes {
            throw NaclScalarMultError.invalidParameters
        }
        
        if p.count != Constants.Scalarmult.bytes {
            throw NaclScalarMultError.invalidParameters
        }
        
        var q = Data(count: Constants.Scalarmult.bytes)
        
        let result = q.withUnsafeMutableBytes { (qPointer: UnsafeMutableRawBufferPointer) -> Int32 in
            return n.withUnsafeBytes { (nPointer: UnsafeRawBufferPointer) -> Int32 in
                return p.withUnsafeBytes { (pPointer: UnsafeRawBufferPointer) -> Int32 in
                    return CTweetNacl.crypto_scalarmult_curve25519_tweet(
                        qPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        nPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        pPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        
        if result != 0 {
            throw NaclScalarMultError.creationFailed
        }
        
        return q
    }
    
    public static func base(n: Data) throws -> Data {
        if n.count != Constants.Scalarmult.scalarBytes {
            throw NaclScalarMultError.invalidParameters
        }
        
        var q = Data(count: Constants.Scalarmult.bytes)
        
        let result = q.withUnsafeMutableBytes { (qPointer: UnsafeMutableRawBufferPointer) -> Int32 in
            return n.withUnsafeBytes { (nPointer: UnsafeRawBufferPointer) -> Int32 in
                return CTweetNacl.crypto_scalarmult_curve25519_tweet_base(
                    qPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    nPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        
        if result != 0 {
            throw NaclScalarMultError.creationFailed
        }
        
        return q
    }
}

// MARK: - Public-key authenticated encryption

public struct NaclBox {
    
    public enum NaclBoxError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    public static func box(message: Data, nonce: Data, publicKey: Data, secretKey: Data) throws -> Data {
        let key = try before(publicKey: publicKey, secretKey: secretKey)
        return try NaclSecretBox.secretBox(message: message, nonce: nonce, key: key)
    }
    
    public static func before(publicKey: Data, secretKey: Data) throws -> Data {
        try NaclUtil.checkBoxLength(publicKey: publicKey, secretKey: secretKey)
        
        var k = Data(count: Constants.Box.beforeNMBytes)
        
        let result = k.withUnsafeMutableBytes { (kPointer: UnsafeMutableRawBufferPointer) -> Int32 in
            return publicKey.withUnsafeBytes { (pkPointer: UnsafeRawBufferPointer) -> Int32 in
                return secretKey.withUnsafeBytes { (skPointer: UnsafeRawBufferPointer) -> Int32 in
                    return CTweetNacl.crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(
                        kPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        pkPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        skPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        
        if result != 0 {
            throw NaclBoxError.creationFailed
        }
        
        return k
    }
    
    public static func open(message: Data, nonce: Data, publicKey: Data, secretKey: Data) throws -> Data {
        let k = try before(publicKey: publicKey, secretKey: secretKey)
        return try NaclSecretBox.open(box: message, nonce: nonce, key: k)
    }
    
    public static func keyPair() throws -> (publicKey: Data, secretKey: Data) {
        let sk = try NaclUtil.secureRandomData(count: Constants.Box.secretKeyBytes)
        
        return try NaclWrapper.crypto_box_keypair(secretKey: sk)
    }
    
    public static func keyPair(fromSecretKey sk: Data) throws -> (publicKey: Data, secretKey: Data) {
        if sk.count != Constants.Box.secretKeyBytes {
            throw NaclBoxError.invalidParameters
        }
        
        return try NaclWrapper.crypto_box_keypair(secretKey: sk)
    }
}

// MARK: - Signatures

public struct NaclSign {
    
    public enum NaclSignError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    public static func sign(message: Data, secretKey: Data) throws -> Data {
        if secretKey.count != Constants.Sign.secretKeyBytes{
            throw NaclSignError.invalidParameters
        }
        
        var signedMessage = Data(count: Constants.Sign.bytes + message.count)
        
        let tmpLength = UnsafeMutablePointer<UInt64>.allocate(capacity: 1)
        
        let result = signedMessage.withUnsafeMutableBytes { (signedMessagePointer: UnsafeMutableRawBufferPointer) -> Int32 in
            return message.withUnsafeBytes { (messagePointer: UnsafeRawBufferPointer) -> Int32 in
                return secretKey.withUnsafeBytes { (secretKeyPointer: UnsafeRawBufferPointer) -> Int32 in
                    return CTweetNacl.crypto_sign_ed25519_tweet(
                        signedMessagePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        tmpLength,
                        messagePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        UInt64(message.count),
                        secretKeyPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        
        if result != 0 {
            throw NaclSignError.internalError
        }
        
        return signedMessage
    }
    
    public static func signOpen(signedMessage: Data, publicKey: Data) throws -> Data {
        if publicKey.count != Constants.Sign.publicKeyBytes {
            throw NaclSignError.invalidParameters
        }
        
        var tmp = Data(count: signedMessage.count)
        let tmpLength = UnsafeMutablePointer<UInt64>.allocate(capacity: 1)
        
        let result = tmp.withUnsafeMutableBytes { (tmpPointer: UnsafeMutableRawBufferPointer) -> Int32 in
            return signedMessage.withUnsafeBytes { (signMessagePointer: UnsafeRawBufferPointer) -> Int32 in
                return publicKey.withUnsafeBytes { (publicKeyPointer: UnsafeRawBufferPointer) -> Int32 in
                    return CTweetNacl.crypto_sign_ed25519_tweet_open(
                        tmpPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        tmpLength,
                        signMessagePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        UInt64(signedMessage.count),
                        publicKeyPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        
        if result != 0 {
            throw NaclSignError.creationFailed
        }
        
        return tmp
    }
    
    public static func signDetached(message: Data, secretKey: Data) throws -> Data {
        let signedMessage = try sign(message: message, secretKey: secretKey)
        
        let sig = signedMessage.subdata(in: 0..<Constants.Sign.bytes)
        
        return sig as Data
    }
    
    public static func signDetachedVerify(message: Data, sig: Data, publicKey: Data) throws -> Bool {
        if sig.count != Constants.Sign.bytes {
            throw NaclSignError.invalidParameters
        }
        
        if publicKey.count != Constants.Sign.publicKeyBytes {
            throw NaclSignError.invalidParameters
        }
        
        var sm = Data()
        
        var m = Data(count: Constants.Sign.bytes + message.count)
        
        sm.append(sig )
        sm.append(message)
        
        let tmpLength = UnsafeMutablePointer<UInt64>.allocate(capacity: 1)
        
        let result = m.withUnsafeMutableBytes { (mPointer: UnsafeMutableRawBufferPointer) -> Int32 in
            return sm.withUnsafeBytes { (smPointer: UnsafeRawBufferPointer) -> Int32 in
                return publicKey.withUnsafeBytes { (publicKeyPointer: UnsafeRawBufferPointer) -> Int32 in
                    return CTweetNacl.crypto_sign_ed25519_tweet_open(
                        mPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        tmpLength,
                        smPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        UInt64(sm.count),
                        publicKeyPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        
        return result == 0
    }
    
    public struct KeyPair {
        public static func keyPair() throws -> (publicKey: Data, secretKey: Data) {
            return try NaclWrapper.crypto_sign_keypair()
        }
        
        public static func keyPair(fromSecretKey secretKey: Data) throws -> (publicKey: Data, secretKey: Data) {
            if secretKey.count != Constants.Sign.secretKeyBytes {
                throw NaclSignError.invalidParameters
            }
            
            let pk = secretKey.subdata(in: Constants.Sign.publicKeyBytes..<Constants.Sign.secretKeyBytes)
            
            return (pk, secretKey)
        }
        
        public static func keyPair(fromSeed seed: Data) throws -> (publicKey: Data, secretKey: Data) {
            if seed.count != Constants.Sign.seedBytes {
                throw NaclSignError.invalidParameters
            }
            
            return try NaclWrapper.crypto_sign_keypair_seeded(secretKey: seed)
        }
    }
}

