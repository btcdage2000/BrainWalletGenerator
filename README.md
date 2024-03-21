Brain Wallet Generator User Guide
脑钱包生成器用户指南

@btcdage
@囤饼达

The Brain Wallet Generator is a simple yet powerful tool that allows users to create a Bitcoin wallet using a passphrase of their choice.
脑钱包生成器是一个简单而强大的工具，允许用户使用他们选择的口令来创建比特币钱包。

This document provides guidance on how to use the Brain Wallet Generator to create your own secure Bitcoin wallet.
本文档提供了如何使用脑钱包生成器创建您自己的安全比特币钱包的指导。

Getting Started
开始使用

Opening the Program:
You can start the Brain Wallet Generator either by running the executable file packaged by Dage, or by running the source code Brain.py (this method ensures that Python and all necessary dependencies are installed on your system).
开始使用
打开程序：
可直接通过运行达哥已经打包好的可执行文件，也可以通过运行源码Brain.py启动脑钱包生成器（此种方式确保您的系统上已安装Python和所有必需的依赖项）。

Entering a Passphrase:
In the program's main window, you will find a field labeled "Passphrase / 脑口令:". Enter a secure and memorable passphrase in this field.
输入口令：在程序的主窗口中，您会找到一个标有 "Passphrase / 脑口令:" 的字段。在此字段中输入一个安全且易于记忆的口令。

Generating the Wallet:
After entering the passphrase, click the "Generate Brain Wallet / 开始计算" button to generate your "one-dimensional wallet address".
生成钱包：输入口令后，点击 "Generate Brain Wallet / 开始计算" 按钮来生成您的“一维钱包地址”。

The program will display several pieces of information, including the hexadecimal encoding, SHA-256 hash, BIP39 mnemonic words, private key, public key, P2PKH address, Bech32 private key, and Bech32 address.
程序将显示多条信息，包括十六进制编码、SHA-256哈希、BIP39助记词、私钥、公钥、P2PKH地址、Bech32私钥和Bech32地址。

Features
Hexadecimal Encoding: Displays the hexadecimal representation of your passphrase.
SHA-256 Hash: Displays the SHA-256 hash value of your passphrase.
BIP39 Mnemonic Words: A set of words generated from your passphrase that can be used to recover your wallet.
Private & Public Keys: The keys required to access and manage your wallet.
P2PKH Address & Bech32 Address: Bitcoin receiving addresses generated from your keys.
功能
十六进制编码：显示您的口令的十六进制表示。
SHA-256哈希：显示您的口令的SHA-256哈希值。
BIP39助记词：从您的口令生成的一组词语，可用于恢复您的钱包。
私钥 & 公钥：访问和管理钱包所需的密钥。
P2PKH地址 & Bech32地址：从您的密钥生成的比特币接收地址。

Advanced Features
Salting and Hash Nesting: Allows for the addition of salt to the passphrase during each hash operation—the salt string is added after the passphrase. Multiple nesting automatically adds salt with each hash.
高级功能
加盐和哈希套娃：可以再每次对脑口令进行哈希时进行加盐操作——盐字符串会加在脑口令后面。多次套娃会自动在每次哈希时自动加盐。

Generate from Mnemonic:
If you have existing BIP39 mnemonic words, you can enter them directly into the "BIP39 Mnemonic Words" field and click the "Generate from mnemonic / 根据助记词生成" button to generate wallet details. (Convenient for managing individual derived addresses, helpful for custodial needs like hodling.)
根据助记词生成：如果您有现有的BIP39助记词，可以直接输入到 "BIP39助记词" 字段中，并点击 "Generate from mnemonic / 根据助记词生成" 按钮来生成钱包详情。（方便单独管理单一派生地址，有助于囤饼代持等需求）

QR Codes:
QR codes are generated next to each piece of wallet information for easy sharing and recording.
二维码：每条钱包信息旁边都生成了二维码，便于分享和记录。

Important Tips
Security: This tool is used to generate one-dimensional brain addresses. Please do not directly use the initial one-dimensional brain address to receive coins. Instead, use the advanced brain method, design your own brain rules, and protect your passphrase and brain rules. Please note: Your passphrase + brain rules, mnemonic words, and private keys should never be disclosed. Anyone who can access them can control your wallet.
重要提示
安全：工具用来生成一维脑地址，请勿直接使用最初的一维脑地址接受币，而是使用高级脑的方式，设计自己的脑规则，并保护好您的脑口令和脑规则。请注意：脑口令+脑规则、助记词、私钥 均不可外泄，任何能够访问它们的人都可以控制您的钱包。

Backup: It is recommended that at least one element of the brain passphrase and rules must be memorized by yourself and your family and not stored in the physical world. Other elements can be backed up in multiple locations.
备份：建议脑口令和闹规则中只要有一个元素必须自己和家人牢牢记住，不保存在物理世界中。其他元素可以备份在多个地点。

Passphrase Strength: Use brain rules to generate a strong and unique passphrase to ensure the security of your wallet.
口令强度：利用闹规则生成强大且独特的口令来确保您钱包的安全。

The Brain Wallet Generator offers a simple method for creating a secure Bitcoin wallet based on a passphrase or mnemonic words. By following the steps outlined in this guide, you can easily generate and manage your own Bitcoin wallet. Remember, security is paramount when dealing with cryptocurrency. Always keep your wallet information private and secure.
脑钱包生成器提供了一种基于口令或助记词创建安全比特币钱包的简单方法。按照本指南中概述的步骤，您可以轻松生成和管理自己的比特币钱包。记住，处理加密货币时，安全至关重要。始终保持您的钱包信息私密和安全。
