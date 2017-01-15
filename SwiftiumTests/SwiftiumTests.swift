//
//  SwiftiumTests.swift
//  SwiftiumTests
//
//  Created by dman on 1/2/17.
//  Copyright © 2017 Daniel Hong. All rights reserved.
//

import XCTest
import Swiftium

extension String {
    func toData() -> NSData? {
        return self.data(using: String.Encoding.utf8, allowLossyConversion: false) as NSData?
    }
}

extension NSData {
    func toString() -> String? {
        return (NSString(data: self as Data, encoding: String.Encoding.utf8.rawValue) as! String)
    }
}

class SwiftiumTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testSecretBox() {
        XCTAssert(Swiftium.setup() == true)
        
        // Some test data
        let msg = "Hello World!".toData()!
        let key1 = Swiftium.utils.randomBytes(len: SecretBox.keySize)!
        let key2 = Swiftium.utils.randomBytes(len: SecretBox.keySize)!
        
        let secretBox = SecretBox()
        
        // Test the easiest way to encrypt with auto generated key
        let (encrypted1, secretKey): (NSData, Key) = try! secretBox.encrypt(message: msg)
        let decrypted1: NSData = try! secretBox.decrypt(nonceMacCipherText: encrypted1, secretKey: secretKey)
        XCTAssert(decrypted1 == msg)
        
        // Test simple combined nonce + mac + cipher text with a provided key
        let encrypted2: NSData = try! secretBox.encrypt(message: msg, secretKey: key1)
        let decrypted2: NSData = try! secretBox.decrypt(nonceMacCipherText: encrypted2, secretKey: key1)
        XCTAssert(decrypted2 == msg)
        
        // Test that encrypting the same plain text with same key should not
        // result in the same cipher text
        XCTAssertNotEqual(encrypted2, try? secretBox.encrypt(message: msg, secretKey: key1))
        
        // Test invalid key on decryption
        XCTAssertNil(try? secretBox.decrypt(nonceMacCipherText: encrypted2, secretKey: key2))
    }
    
    func testUtils() {
        XCTAssert(Swiftium.setup() == true)
        
        // Some test data
        let d1 = NSData(bytes: [1, 2, 3, 4] as [UInt8], length: 4)
        let d2 = NSData(bytes: [1, 2, 3, 4] as [UInt8], length: 4)
        let d3 = NSData(bytes: [0, 1, 2, 3] as [UInt8], length: 4)
        let d4 = NSData(bytes: [0, 1, 2] as [UInt8], length: 3)
        let md1 = NSMutableData(bytes: [1, 2, 3, 4] as [UInt8], length: 4)
        
        // Testing comparison
        XCTAssert(Swiftium.utils.compare(d1, d2)! == 0)
        XCTAssert(Swiftium.utils.compare(d1, d3)! == 1)
        XCTAssert(Swiftium.utils.compare(d3, d1)! == -1)
        XCTAssert(Swiftium.utils.compare(d1, d4) == nil)
        
        // Testing equality
        XCTAssert(Swiftium.utils.equals(d1, d2) == true)
        XCTAssert(Swiftium.utils.equals(d1, d3) == false)
        XCTAssert(Swiftium.utils.equals(d1, d4) == false)
        
        // Zero the data
        Swiftium.memory.zero(data: md1)
        
        // Test that data was indeed zeroed
        XCTAssert(Swiftium.memory.isZero(data: md1) == true)
        
        // Test data that is not zero
        XCTAssert(Swiftium.memory.isZero(data: d1) == false)
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    
}
