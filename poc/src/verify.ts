
import transmute from '@transmute/verifiable-credentials'

// space is caused by a bug related to python / json stringify.
const iriPrefix = `data: application/vc+ld+json+sd-jwt;`

export type VerifiableCredential = {
  '@context': [ 'https://www.w3.org/ns/credentials/v2' ]
  type: ['VerifiableCredential']
  issuer: {
    id: string
  }
  validFrom: string
  credentialSubject: Record<string, any>
}

export type VerifiablePresentation = {
  '@context': [ 'https://www.w3.org/ns/credentials/v2' ]
  type: ['VerifiablePresentation']
  verifiableCredential: Array<string | VerifiableCredential>
}

export type VerifiedConformingDocument = VerifiableCredential | VerifiablePresentation

export async function verify(token: string, jwks: any, options:any): Promise<VerifiedConformingDocument[]>{
  if (options.presentation_content_type !== 'application/vp+ld+json+sd-jwt'){
    throw new Error("Unsupported presentation content type")
  }
  const conformingDocuments = []
  const resolver = {
    resolve: async (kid: string) => {
      const jwk = jwks.keys.find((jwk:any) => {
        return kid === jwk.kid
      })
      if (!jwk) {
        throw new Error('Unsupported kid: ' + kid)
      }
      return jwk
    }
  }
  const verifiedPresentation = await transmute.vc.sd.verifier({
    resolver
  })
  .verify({
    token: token,
    audience: options.presentation_audience,
    nonce: options.presentation_nonce
  })
  // console.info('presentation verified.')
  conformingDocuments.push(verifiedPresentation.claimset as VerifiablePresentation)
  for (const index in verifiedPresentation.claimset.verifiableCredential){
    const credential = verifiedPresentation.claimset.verifiableCredential[index]
    if (!credential.startsWith(iriPrefix)){
      throw new Error("Unsupported credential type")
    }
    const issuerSignedJwtWithDisclosuresAndKeyBindingToken = credential.replace(iriPrefix, '')
    const verifiedCredential = await transmute.vc.sd.verifier({
      resolver
    })
    .verify({
      token: issuerSignedJwtWithDisclosuresAndKeyBindingToken,
      audience: options.credential_audiences[index],
      nonce: options.credential_nonces[index]
    })
    // console.info('credential verified.')
    conformingDocuments.push(verifiedCredential.claimset as VerifiableCredential)
  }
  return conformingDocuments;
} 