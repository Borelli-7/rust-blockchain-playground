# Security Policy

## ⚠️ Educational Project Notice

**keygen-rs is an EDUCATIONAL PROJECT designed for learning purposes.**

This implementation has **NOT** been:
- Professionally audited
- Reviewed by cryptography experts
- Tested for production security requirements
- Verified for resistance to side-channel attacks
- Validated for compliance with security standards

## DO NOT Use in Production

❌ **DO NOT** use this library for:
- Production applications
- Systems handling real user data
- Financial or cryptocurrency applications
- Security-critical infrastructure
- Any scenario where security matters

✅ **DO** use this library for:
- Learning how Ed25519 works
- Understanding elliptic curve cryptography
- Educational demonstrations
- Code study and research

## Use Audited Libraries Instead

For production use, use these well-established, audited cryptographic libraries:

### Recommended Alternatives

1. **[ring](https://github.com/briansmith/ring)**
   - Professionally audited
   - Used in production by major companies
   - Constant-time operations
   - Best choice for security-critical applications

2. **[ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)**
   - Pure Rust implementation
   - Widely used and tested
   - Active maintenance
   - Good performance

3. **[RustCrypto](https://github.com/RustCrypto)**
   - Comprehensive cryptographic ecosystem
   - Multiple algorithm support
   - Community-driven

4. **[libsodium](https://github.com/jedisct1/libsodium)** (via [sodiumoxide](https://github.com/sodiumoxide/sodiumoxide))
   - Battle-tested C library
   - Rust bindings available
   - Easy to use API

## Known Limitations

This educational implementation may have:

1. **Timing Side-Channels**
   - Operations may not be fully constant-time
   - Vulnerable to timing attacks in theory

2. **No Hardware Optimization**
   - Does not use AVX2/NEON SIMD instructions
   - Slower than optimized implementations

3. **Limited Testing**
   - Tested against RFC 8032 vectors
   - Not exhaustively fuzzed or stress-tested

4. **No Expert Review**
   - Implementation by a learning developer
   - Not reviewed by cryptography professionals

5. **Memory Safety**
   - While Rust provides memory safety
   - Sensitive data handling may have vulnerabilities

## Reporting Security Issues

Since this is an educational project, security issues are expected and welcomed as learning opportunities!

If you find security issues:

1. **Open a GitHub Issue** - This is educational, so public disclosure is fine
2. **Label it "security"** - Help others learn from the issue
3. **Explain the vulnerability** - Educational detail appreciated
4. **Suggest improvements** - Help make this a better learning resource

## Learning Resources

To understand why production cryptographic code requires:
- Professional audits
- Extensive testing
- Expert review
- Formal verification (in some cases)

Read:
- [Implementing Curve25519/Ed25519](https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/)
- [A Graduate Course in Applied Cryptography](http://toc.cryptobook.us/)
- [Cryptographic Right Answers](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html)

## Educational Disclaimer

This code is provided "AS IS" without warranty of any kind. The author assumes no liability for any damages from use of this software. 

**Remember**: Real cryptography is hard. Learning implementations like this are great for education, but production systems require libraries built by experts with extensive testing, auditing, and validation.

---

**Last Updated**: February 2026
