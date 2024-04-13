# Changelog

## 0.5.0 (2024-04-14)

 - Switch to using BouncyCastle.Cryptography package and update to the latest version 2.3.0.
 - Internal code refactoring due to BouncyCastle.Cryptography library API changes.
 - Updated unit tests that were failing due to BouncyCastle.Cryptography library API changes.
 - Updated main project to target .NET Framework 4.6.1 (required by BouncyCastle.Cryptography).
 - Updated test project to target .NET Framework 4.6.2 (required by NUnit).

## 0.4.0 (2023-09-30)

 - Updated Portable.BouncyCastle package to the latest version 1.9.0.
 - Marked GetSignatureAlgorithm method in X509CertificateBuilder class as virtual to allow its behavior to be overridden.
 - Removed 3072-bit RSA key algorithm mapping and updated exception message to better reflect behavior.
 - Updated unit tests.

## 0.3.0 (2020-11-13)

 - Switch to using Portable.BouncyCastle package and update to the latest version 1.8.8.
 - Added unit tests.

## 0.2.3 (2020-09-19)

 - Added the ability to generate certificates with random serial numbers.

## 0.2.2 (2020-08-28)

- Minor code improvements.

## 0.2.1 (2020-08-24)

- Minor code improvements.

## 0.2.0 (2020-05-21)

- Updated BouncyCastle package to the latest version 1.8.6.1.

## 0.1.0 (2020-05-06)

- First version. No release history before this.