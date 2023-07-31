import { WebAuthn } from '@dfns/sdk-webauthn'

const asUrl = (path: string): URL => new URL(path, process.env.REACT_APP_API_URL!)

const get = async (path: string): Promise<any> => {
  const res = await fetch(asUrl(path), {
    method: 'GET',
    credentials: 'include',
  })
  return res.json()
}

const post = async (path: string, body: any): Promise<any> => {
  const res = await fetch(asUrl(path), {
    method: 'POST',
    body: JSON.stringify(body),
    headers: {
      'content-type': 'application/json',
    },
    credentials: 'include',
  })
  return res.status !== 204 ? res.json() : undefined
}

export const api = {
  async login(username: string, password: string): Promise<{ username: string }> {
    return post('/login', { username, password })
  },

  async register(username: string, password: string): Promise<any> {
    const challenge = await post('/register/init', { username, password })

    const webauthn = new WebAuthn({ rpId: process.env.REACT_APP_DFNS_WEBAUTHN_RPID! })
    // @ts-ignore
    const attestation = await webauthn.create(challenge)

    return post('/register/complete', {
      signedChallenge: { firstFactorCredential: attestation },
      temporaryAuthenticationToken: challenge.temporaryAuthenticationToken,
    })
  },

  async sendNativeToAddress(address: string): Promise<any> {
    const { challenge, body, walletId } = await post('/wallets/erc-tx', { address })
    const webauthn: any = new WebAuthn({ rpId: process.env.REACT_APP_DFNS_WEBAUTHN_RPID! })

    const assertion = await webauthn.sign(challenge.challenge, challenge.allowCredentials)

    return post('/wallets/erc-tx/complete', {
      body,
      walletId,
      signedChallenge: { challengeIdentifier: challenge.challengeIdentifier, firstFactor: assertion },
    })
  },

  //send erc20 tokens
  async sendERCToken(address: string): Promise<any> {
    const { challenge, body, walletId } = await post('/wallets/erc', { address })
    const webauthn: any = new WebAuthn({ rpId: process.env.REACT_APP_DFNS_WEBAUTHN_RPID! })

    const assertion = await webauthn.sign(challenge.challenge, challenge.allowCredentials)

    return post('/wallets/erc/complete', {
      body,
      walletId,
      signedChallenge: { challengeIdentifier: challenge.challengeIdentifier, firstFactor: assertion },
    })
  },

  async listWallets() {
    return get('/wallets/list')
  },

  async geWalletAssets(walletId: string) {
    return get('/wallets/assets')
  },

  async createWallet(network: string) {
    const {
      requestBody,
      challenge: { challenge, challengeIdentifier, allowCredentials },
    } = await post('/wallets/new/init', { network })

    const webauthn = new WebAuthn({ rpId: process.env.REACT_APP_DFNS_WEBAUTHN_RPID! })
    const assertion = await webauthn.sign(challenge, allowCredentials)

    await post('/wallets/new/complete', {
      requestBody,
      signedChallenge: { challengeIdentifier, firstFactor: assertion },
    })
  },

  async recoverWalletWithUsername(username: string) {
    console.log('hitting')
  },

  async onGenSig() {
    const { challenge, walletId, allowCredentials, challengeIdentifier, ...data } = await post('/wallet/sig', {
      walletId: 'wa-4a5er-0ue3t-9l28e48vj4p7eklm',
    })

    console.log(data)

    const webauthn = new WebAuthn({ rpId: process.env.REACT_APP_DFNS_WEBAUTHN_RPID! })
    const assertion = await webauthn.sign(challenge, allowCredentials)

    await post('/wallet/sig/complete', {
      signedChallenge: { challengeIdentifier, firstFactor: assertion },
      walletId,
      ...data,
    })
  },
}
