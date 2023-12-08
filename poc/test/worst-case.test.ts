
import * as api from '../src'

const alg = 'ES384'

const credential_audience = 'california.dmv.verifier.example'
const credential_nonce = 'state-driver-license-required-documents-presentation-123'

const presentation_audience = 'san-francisco.dmv.verifier.example'
const presentation_nonce = 'city-driver-license-required-documents-presentation-456'


describe('worst case', () => {
  it('assume aud and nonce are present everywhere', async () => {
    const issuerRole = await api.vc.sd.key.generate(alg)
    const holderRole = await api.vc.sd.key.generate(alg)
    const jwks ={
      keys: [ issuerRole.publicKeyJwk, holderRole.publicKeyJwk ]
    }
    const issuerSignedJwtWithDisclosures = await api.vc.sd.issuer({
      kid: issuerRole.publicKeyJwk.kid,
      secretKeyJwk: issuerRole.secretKeyJwk
    })
    .issue({
      holder: holderRole.publicKeyJwk.kid,
      claimset: `
"@context":
  - https://www.w3.org/ns/credentials/v2
type:
  - VerifiableCredential
issuer:
  id: https://issuer.example
validFrom: 2015-05-10T12:30:00Z
credentialSubject:
  !sd id: did:example:ebfeb1f712ebc6f1c276e12ec21
    `.trim()
    })
    const issuerSignedJwtWithDisclosuresAndKeyBindingToken = await api.vc.sd.holder({
      kid: holderRole.publicKeyJwk.kid,
      secretKeyJwk: holderRole.secretKeyJwk
    })
    .issue({
      token: issuerSignedJwtWithDisclosures,
      audience: credential_audience,
      nonce: credential_nonce,
      disclosure: `
"@context":
  - https://www.w3.org/ns/credentials/v2
type:
  - VerifiableCredential
issuer:
  id: https://issuer.example
validFrom: 2015-05-10T12:30:00Z
credentialSubject:
  id: True
    `.trim()
    })

    const holderSignedJwtWithDisclosures = await api.vc.sd.issuer({
      kid: holderRole.publicKeyJwk.kid,
      secretKeyJwk: holderRole.secretKeyJwk
    })
    .issue({
      holder: holderRole.publicKeyJwk.kid,
      claimset: `
"@context":
  - https://www.w3.org/ns/credentials/v2
type:
  - VerifiablePresentation
verifiableCredential:
  - !sd "data:application/vc+ld+json+sd-jwt;${issuerSignedJwtWithDisclosuresAndKeyBindingToken}"
    `.trim()
    })

    const holderSignedJwtWithDisclosuresAndKeyBindingToken = await api.vc.sd.holder({
      kid: holderRole.publicKeyJwk.kid,
      secretKeyJwk: holderRole.secretKeyJwk
    })
    .issue({
      token: holderSignedJwtWithDisclosures,
      audience: presentation_audience,
      nonce: presentation_nonce,
      disclosure: `
"@context":
  - https://www.w3.org/ns/credentials/v2
type:
  - VerifiablePresentation
verifiableCredential:
  - True
    `.trim()
    })

    const conformingDocuments = await api.verify(holderSignedJwtWithDisclosuresAndKeyBindingToken, jwks, {
      presentation_content_type: 'application/vp+ld+json+sd-jwt',
      presentation_audience,
      presentation_nonce,
      credential_audiences: [
        credential_audience
      ],
      credential_nonces: [
        credential_nonce
      ]
    })
    expect(conformingDocuments.length).toBe(2)
    expect(conformingDocuments[0].type).toEqual(['VerifiablePresentation'])
    expect(conformingDocuments[1].type).toEqual(['VerifiableCredential'])
  })
})