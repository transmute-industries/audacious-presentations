# Audacious Presentations

This repo is dedicated to eliminating confusion related to:

- [W3C Verifiable Credentials](https://w3c.github.io/vc-data-model/#credentials)
- [W3C Verifiable Presentations](https://w3c.github.io/vc-data-model/#presentations) 
- [IETF SD-JWT](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)

and the concept of audience and nonce context binding.

## Introduction

Sometimes credential claimset's contain claims indicating an [audience](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3).
W3C Data Integrity Proofs use the term [domain](https://w3c.github.io/vc-data-integrity/#dfn-domain).

When present this claim indicates the intendened recipient / context for the credential / presentation.

There is also [nonce](https://www.rfc-editor.org/rfc/rfc9449.html#name-nonce-registration-update).

W3C Data Integrity Proofs use the term [challenge](https://w3c.github.io/vc-data-integrity/#dfn-challenge).

When present this claim allows the signer to commit to some value that might be acceptable to a verifier.
A common use for this claim is replay attack mitigation, or proving possession of a key at a point in time.

These claims are "protocol claims" in the sense that they are only in the claimset data model to assist with protocols that require them.

When implemented incorrectly, they can create security issues, such as replay attack vulnerabilities, or attacks related to key theft, or signing capabilty theft over time.

They are critical to the security of authentiation protocols.

## The Problem

A "presentation" is both an action performed by an entity and a concrete data structure that can be serialized in various different ways.

A "W3C Verifiable Presentation" is one concrete serialization of a "presentation", it is a compact JSON-LD Document.

This is the minimal specification legal W3C Verifiable Presentation:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
  ],
  "type": "VerifiablePresentation"
}
```

This data structure is problematic, because it is a protocol specific data structure, in a data model specification.

The value of this data structure, comes from use of its optional elements, for example:

Delivering multiple verifiable credentials (without integrity protection or context binding):

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
  ],
  "type": "VerifiablePresentation",
  "verifiableCredentials": [
    "data:application/vc+ld+json+sd-jwt;eyJhbGciOiJFUzM4N...", // secured with key binding 
    "data:application/vc+ld+json+sd-jwt;eyJhbGciDFkfld5Sl...", // secured with no key binding
    { // no binding and no security.
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
      ],
      "id": "http://university.example/credentials/1872",
      "type": ["VerifiableCredential", "ExampleAlumniCredential"],
      "issuer": "https://university.example/issuers/565049",
      "validFrom": "2010-01-01T19:23:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "alumniOf": {
          "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
          "name": "Example University"
        }
      }
    }
  ]
}
```

In this example, we don't know the "audience" or "domain" for which this presentation has been constructed,
and even if we did, without integrity protection, that information MUST NOT be trusted.

As soon as we add presentation security, a problem arises where the "audience / domain" and "nonce / challenge"
become only safely interpretted in the context of a protocol.

The verifier MUST reject values that are not acceptable, and these values can appear in several places, lets look at a concrete example.

Consider a secured SD-JWT W3C Verifiable Presentation (`application/vp+ld+json+sd-jwt`) with key binding.

After verifying the secured presentation, a conforming document that looks like this is produced:

```json
{
  "iat": 1702050252,
  "exp": 1733672652,
  "aud": "https://verifier.example",
  "nonce": "1702050252",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-384",
      "alg": "ES384",
      "x": "3TN7bhuYDWU7EtlObes_N8ZFLHpRqBVi6pmajLxUPHftphsgXrVdAyn6_L1ZmNG2",
      "y": "mvDB6lQTqT8wnPf_wcHiX_pi2sPsUO6r5vpiEK9EDiDK0-ntMGCAYc5TR931b1Fl"
    }
  },
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
  ],
  "type": "VerifiablePresentation",
  "verifiableCredentials": [
    "data:application/vc+ld+json+sd-jwt;eyJhbGciOiJFUzM4N...", // secured with key binding 
    "data:application/vc+ld+json+sd-jwt;eyJhbGciDFkfld5Sl...", // secured with no key binding
    { // no binding and no security.
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
      ],
      "id": "http://university.example/credentials/1872",
      "type": ["VerifiableCredential", "ExampleAlumniCredential"],
      "issuer": "https://university.example/issuers/565049",
      "validFrom": "2010-01-01T19:23:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "alumniOf": {
          "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
          "name": "Example University"
        }
      }
    }
  ]
}
```

In the API to verify, the audience it typically supplied, see this JWT API for example:

- [example verify api](https://github.com/panva/jose/blob/main/docs/functions/jwt_verify.jwtVerify.md)

In the example above there are a number of challenges, that prevent a simple and safe verification API from being possible to implement:

There are 2 Key Binding Tokens
  - 1 for the outer presentation
  - 1 for the inner [Fnord](https://github.com/oauth-wg/oauth-selective-disclosure-jwt/pull/394))

There are 7x `aud` claims
  - 1 for the outer presentation
  - 1 for the outer presentation key binding
  - 1 for the first credential
  - 1 for the first credential key binding
  - 1 for the second credential
  - 1 for the second credential key binding
  - 1 for the third credential (the json one)

Assuming there would be consensus to forbid `aud` from being present in `application/vc+ld+json` and `application/vp+ld+json`.

There are now 2 `aud` claims:
  - 1 for the outer presentation key binding
  - 1 for the first credential key binding

A hypothetical api for verifying such a presentation would look like this:

```ts
const verifiedConformingDocuments = verify<W3C_VP_SD_JWT>(token: string, jwks: JsonWebKeySet, {
  presentation_content_type: 'application/vp+ld+json+sd-jwt',
  presentation_audience: 'verifier.example'
  credential_audiences: [
    'mediator-1.example',
    // 'mediator-2.example', in the case the second credential also had key binding
  ]
})
```

The when successful, the `verifiedConformingDocuments` is an unordered set of 
verifiable credentials INFRA Maps conforming to the normative statements associated with the (`application/vc+ld+json`).

These documents can then have their conformance checked, for example, ensuring XMLDataTimes and URLs are well formed.

A verifier SHOULD / MUST? reject presentations with audiences that it was not expecting, 
as this would indicate a presentation was being made to a party that was not expecting to receive one, 
and since presentations contain PII, it could create problems to process this data.

Sending a presentation to the wrong verifier, is similar to faxing a patient's medical records to the wrong phone number.

In the case a verifier wanted to confirm `nonce / challenge` as well as `aud / domain` a hypothetical verification API might look like:

```ts
const verifiedConformingDocuments = verify<W3C_VP_SD_JWT>(token: string, jwks: JsonWebKeySet, {
  presentation_content_type: 'application/vp+ld+json+sd-jwt',
  presentation_audience: 'california.dmv.verifier.example'
  presentation_nonce: 'state-driverse-license-required-documents-presentation-546564646546516',
  credential_audiences: [
    'san-francisco.dmv.verifier.example',
  ],
  credential_nonces: [
    'city-driverse-license-required-documents-presentation-546564646546516',
  ]
})
```

The problem is slightly further compounded with selective disclosure, which could be used with `audience / domain`.

For example, a state dmv might bind a credential to 3 regional offices for presentation, 
but revealing all 3 would allow for strong location tracking of the subject's home address.

Although this example is contrived, it can be common to bind a [credential to multiple audiences](https://stackoverflow.com/questions/73275113/openid-connect-multiple-audiences-in-access-token).

Data minimization best practices suggest that all information not needed by a verifier to perform its business function should be redacted in presentations.

Although these examples focus on SD-JWT, similar issues exist with Data Integrity Proofs that support selective disclosure.

## Recommendations

1. Provide guidance in the core data model specifiation on "context / transaction binding", but do not recommend specific protocols.
2. Provide MAY / MUST / MUST NOT / SHOULD NOT guidance regarding `nonce / challenge` as well as `aud / domain` and cover both the inner credentials as well as the outer credentials.
3. Consider removing `VerifiablePresentations` from the core data model, or making additional properties required to improve interoperability in protocols that build on this data structure, which is designed for use in protocols.

Regarding bullet point 3, the following properties would be good candidates to provide stronger normative guidance for:

1. [holder](https://w3c.github.io/vc-data-model/#dfn-holders).
2. aud / domain : not currently defined in the core data model.
3. nonce / challenge: not currently defined in the core data model.