# Encrypt and decrypt file content.

AES encryption and decryption can be performed on file content.
DES3 encryption and decryption can be performed on file content.
Blowfish encryption and decryption can be performed on file content.
RSA encryption and decryption can be performed on file content.

Note: RSA belongs to asymmetric algorithms, which are generally not suitable for encrypting large file contents. Therefore, the RSA encryption function in this project actually uses Blowfish to encrypt data content first, and then RSA encrypts its Blowfish key, which is essentially a hybrid encryption.

File formats that support encryption and decryption:.txt、.mp4、.jpg、.pdf、.docx、.xlsx

After encryption, it will be saved as a new file and a key file will be generated to store the key,New files will also be generated during decryption.

The encrypted file will increase the file size and when opened, files in formats other than txt will show file damage and cannot be viewed properly,can only be viewed normally after decryption.

可以对文件内容执行AES加密和解密;可以对文件内容执行DES3加密和解密;可以对文件内容执行Blowfish加密和解密;可以对文件内容执行RSA加密和解密。

注：RSA属于非对称算法，非对称算法一般不适用加密大文件内容，所以该项目中RSA加密功能实际是先使用Blowfish加密数据内容然后对其Blowfish密钥进行RSA加密，本质为混合加密。

支持加密和解密的文件格式：.txt、.mp4、.jpg、.pdf、.docx、.xlsx、.jpeg、.png

加密后，它将另存为新文件，并生成一个密钥文件来存储密钥，解密过程中也会生成新文件。

加密文件将增加文件大小，打开时，txt以外格式的文件将显示文件损坏，无法正常查看，只能在解密后正常查看。
