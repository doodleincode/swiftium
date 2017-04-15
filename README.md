# A libsodium wrapper for Swift 3
Swiftium is a lightweight libsodium wrapper for Swift 3. Only supports the secretbox "easy" functions of libsodium as well as a few of the helper/utility functions.

Tested against libsodium 1.0.11. A precompiled libsodium binary is included with this repo, however I recommend that you compile your own from source. View the install docs for instructions https://download.libsodium.org/doc/installation/.

The source directory is a little messy. I wish groups in Xcode would create a physical folder as well. All of the *.swift files and Swiftium.h are part of the Swiftium library. The rest of the files are libsodium’s headers and binary files which can be replaced with the ones you download from source and compile.

# Usage example

There isn't too much to Swiftium, but here's a quick start guide. You can view the test script for a few more examples.

### Create a key
    let key = Swiftium.utils.randomBytes(len: SecretBox.keySize)!

### Create instance of Swiftium SecretBox
    let secretBox = SecretBox()

### Encrypt
    let plainText = "Hello World!".toData()!
    let encrypted: NSData = try! secretBox.encrypt(message: plainText, secretKey: key)

### Decrypt
    let decrypted: NSData = try! secretBox.decrypt(nonceMacCipherText: encrypted, secretKey: key)
    print(decrypted) // Should print Hello World!
