# Experimental Dilithium Blind Signature Library for Digital Payments

This experimental library provides a secure implementation of blind signatures using the Dilithium post-quantum digital signature scheme. It is designed for use in digital payment systems, where preserving payer privacy is crucial.

## Overview

Blind signatures allow a message to be signed without revealing its content to the signer, crucial for maintaining payer privacy in digital payment systems. The Dilithium post-quantum digital signature scheme, a lattice-based cryptographic scheme, offers robust security against both classical and quantum adversaries, making it an ideal choice for future-proofing digital transactions.

The library includes a `DilithiumBlindSignature` class for blind signature operations and a `DigitalPayment` class for creating, signing, and verifying payment requests.

## Choice of Blind Signatures

Blind signatures are pivotal in privacy-preserving digital payment systems, enabling payers to secure a signature on a payment request without disclosing transaction details to the signer. This mechanism ensures the confidentiality of the payer's identity and transaction history, even in untrusted environments.

## Choice of Dilithium

[Dilithium](https://eprint.iacr.org/2017/633.pdf) is a lattice-based post-quantum digital signature scheme recognized for its resistance to both classical and quantum computing threats. Its inclusion in the NIST Post-Quantum Cryptography Standardization process underscores its security efficacy and performance, making it suitable for digital payment systems requiring enduring security measures.

## Example Usage

### Key Generation

Generate a key pair using Dilithium:

```python
from blind_signature_digital_payment import DilithiumBlindSignature

payer_secret_key, payer_public_key = DilithiumBlindSignature.generate_keypair()
```

### Payment Request Creation

Create a payment request:
```
from blind_signature_digital_payment import DigitalPayment

payment = DigitalPayment()
payment_id = "123abc"
amount = 42.0

payment_request = payment.create_payment_request(payer_public_key, amount, payment_id)
```

### Blinding and Unblinding

Generate a blinding factor, blind the payment request, then unblind the signed request:

```
blinding_factor, blinding_factor_inv = DilithiumBlindSignature.generate_blinding_factor()
blinded_payment_request = DilithiumBlindSignature.blind(payment_request_json, blinding_factor)

# After obtaining the issuer's signature on the blinded request
signed_payment_request = DilithiumBlindSignature.unblind(signed_blinded_payment_request, blinding_factor_inv)
```

### Payment Request Signing and Verification

Issuer signs the blinded payment request; payer verifies the signed request:
```
issuer_secret_key = b"issuer_secret_key_placeholder"
signed_blinded_payment_request = DilithiumBlindSignature.sign(issuer_secret_key, blinded_payment_request)

issuer_public_key = b"issuer_public_key_placeholder"
is_valid = payment.verify_payment_request(payment_request, signed_payment_request.hex(), issuer_public_key)

if is_valid:
    print("Payment request is valid.")
else:
    print("Payment request is not valid.")
```

## Future Work and Needs

The current implementation lays the groundwork for privacy-preserving digital payments, highlighting areas for future enhancements, including support for additional signature schemes, performance optimizations, higher-level APIs, interoperability, formal security analysis, comprehensive testing, user-friendly documentation, and community engagement.

## Disclaimer
* **Active Experimentation** - This library is under active development and not suited for production use. It aims to facilitate educational and research activities.
* **Security Audit Required** - Prior to production deployment, a thorough security audit is essential to address potential vulnerabilities.

By using this library, you acknowledge and understand the risks associated with its experimental status and the need for a security audit. The developers and contributors of this library shall not be held responsible or liable for any damages, losses, or issues that may arise from using this library in its current state.

## License

This implementation is released under the MIT License. See the [LICENSE](./LICENSE) file for details.
