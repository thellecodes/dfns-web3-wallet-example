import { DfnsApiClient, DfnsAuthenticator } from '@dfns/sdk'
import { AsymmetricKeySigner } from '@dfns/sdk-keysigner'
import { BaseAuthApi } from '@dfns/sdk/baseAuthApi'
import { UserAuthKind } from '@dfns/sdk/codegen/datamodel/Auth'
import { BlockchainNetwork } from '@dfns/sdk/codegen/datamodel/Foundations'
import { IdentityKindCustomerFacing } from '@dfns/sdk/codegen/datamodel/Permissions'
import { TransferKind } from '@dfns/sdk/codegen/datamodel/Wallets'
import { DfnsDelegatedApiClient } from '@dfns/sdk/dfnsDelegatedApiClient'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import { randomUUID } from 'crypto'
import dotenv from 'dotenv'
import express, { Express, NextFunction, Request, Response } from 'express'
import asyncHandler from 'express-async-handler'

dotenv.config()

const { DFNS_PRIVATE_KEY, DFNS_CRED_ID, DFNS_APP_ORIGIN, DFNS_APP_ID, DFNS_AUTH_TOKEN, DFNS_API_URL, DFNS_ORG_ID } =
  process.env

const apiClient = () => {
  const signer = new AsymmetricKeySigner({
    privateKey: DFNS_PRIVATE_KEY as string,
    credId: DFNS_CRED_ID as string,
    appOrigin: DFNS_APP_ORIGIN as string,
  })

  return new DfnsApiClient({
    appId: DFNS_APP_ID as string,
    authToken: DFNS_AUTH_TOKEN as string,
    baseUrl: DFNS_API_URL as string,
    signer,
  })
}

const delegatedClient = (authToken: string) => {
  return new DfnsDelegatedApiClient({
    appId: DFNS_APP_ID!,
    authToken,
    baseUrl: DFNS_API_URL!,
  })
}

;(async () => {
  try {
    const recover = await apiClient().auth.createUserRecovery({
      body: {
        username: 'sam',
        orgId: DFNS_ORG_ID!,
      },
    })
  } catch (err) {
    console.log(err)
  }
})()

const auth = (req: Request, res: Response, next: NextFunction) => {
  if (req.cookies.DFNS_AUTH_TOKEN) {
    next()
  } else {
    res.status(401).json({
      error: 'not authenticated',
    })
  }
}

const app: Express = express()
app.use(cors({ origin: 'http://localhost:3000', credentials: true }))
app.use(cookieParser())
app.use(express.json())

app.get('/', (req: Request, res: Response) => {
  res.send('DFNS delegated auth example server')
})

app.post(
  '/login',
  asyncHandler(async (req: Request, res: Response) => {
    // perform local system login before log into DFNS with delegated login

    const login = await apiClient().auth.createDelegatedUserLogin({
      body: { username: req.body.username },
    })

    // cache the DFNS auth token, example uses a client-side cookie, but can be
    // cached in other ways, such as session storage or database
    res.cookie('DFNS_AUTH_TOKEN', login.token, { maxAge: 900000, httpOnly: true }).json({ username: req.body.username })
  })
)

app.post(
  '/register/init',
  asyncHandler(async (req: Request, res: Response) => {
    // perform local system registration before initiating DFNS registration
    try {
      const challenge = await apiClient().auth.createDelegatedUserRegistration({
        body: { kind: UserAuthKind.EndUser, email: req.body.username },
      })

      res.json(challenge)
    } catch (err) {
      console.log(err)
    }

    return
    const signer = new AsymmetricKeySigner({
      privateKey: process.env.DFNS_PRIVATE_KEY!,
      credId: process.env.DFNS_CRED_ID!,
      appOrigin: process.env.DFNS_APP_ORIGIN!,
    })

    const dfnsApi = new DfnsApiClient({
      appId: process.env.DFNS_APP_ID!,
      authToken: process.env.DFNS_AUTH_TOKEN!,
      baseUrl: process.env.DFNS_API_URL!,
      signer,
    })

    const wallet = await dfnsApi.wallets.createWallet({ body: { network: BlockchainNetwork.ETH_GOERLI } })
    console.log(JSON.stringify(wallet))

    const list = await dfnsApi.wallets.listWallets({})
    console.log(JSON.stringify(list))
  })
)

app.post(
  '/register/complete',
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    try {
      const registration = await BaseAuthApi.createUserRegistration(req.body.signedChallenge, {
        appId: DFNS_APP_ID!,
        baseUrl: DFNS_API_URL!,
        authToken: req.body.temporaryAuthenticationToken,
      })

      const client = apiClient()

      const permission = await client.permissions.createPermission({
        body: {
          name: `wallets permissions for ${registration.user.id}`,
          operations: ['Wallets:Create', 'Wallets:Read', 'Wallets:TransferAsset'],
        },
      })

      await client.permissions.createPermissionAssignment({
        body: {
          permissionId: permission.id,
          identityKind: IdentityKindCustomerFacing.EndUser,
          identityId: registration.user.id,
        },
      })

      res.json({ username: registration.user.username })
    } catch (err) {
      console.log(err)
      return res.status(400)
    }
  })
)

app.use(auth)

app.get(
  '/wallets/list',
  asyncHandler(async (req: Request, res: Response) => {
    const wallets = await delegatedClient(req.cookies.DFNS_AUTH_TOKEN).wallets.listWallets({})

    res.json(wallets)
  })
)

app.get(
  '/wallets/assets',
  asyncHandler(async (req: Request, res: Response) => {
    let userAssets: any = {}

    const wallets = await delegatedClient(req.cookies.DFNS_AUTH_TOKEN).wallets.listWallets({})

    for (let i = 0; i < wallets.items.length; i++) {
      const eachWalletId: string = wallets.items[i].id
      const wallet = await delegatedClient(req.cookies.DFNS_AUTH_TOKEN).wallets.getWalletAssets({
        walletId: eachWalletId,
      })

      userAssets[wallet.network] = wallet.assets
    }

    res.json(userAssets)
  })
)

app.post('/wallets/new/init', async (req: Request, res: Response) => {
  // transform user inputs to a DFNS request body before initiating action signing flow

  const body = {
    network: req.body.network,
    externalId: randomUUID(),
  }

  const challenge = await delegatedClient(req.cookies.DFNS_AUTH_TOKEN).wallets.createWalletInit({ body })

  res.json({
    requestBody: body,
    challenge,
  })
})

app.post('/wallets/erc-tx', async (req: Request, res: Response) => {
  const { address } = req.body
  const walletId = 'wa-7v6u2-57qfi-8gca84e02i3givaq'

  const body = { kind: TransferKind.Native, to: address, amount: '1000000000' }

  const challenge = await delegatedClient(req.cookies.DFNS_AUTH_TOKEN).wallets.transferAssetInit({
    walletId,
    body: { kind: TransferKind.Native, to: address, amount: '1000000000' },
  })

  res.json({ address, challenge, walletId, body })
})

app.post('/wallets/erc-tx/complete', async (req: Request, res: Response) => {
  const { signedChallenge, body, walletId } = req.body

  const trx = await delegatedClient(req.cookies.DFNS_AUTH_TOKEN).wallets.transferAssetComplete(
    {
      walletId,
      body,
    },
    signedChallenge
  )

  res.send(trx)
})

app.post('/wallets/erc', async (req: Request, res: Response) => {
  const { address } = req.body
  const walletId = 'wa-7v6u2-57qfi-8gca84e02i3givaq'
  const contract = '0x2DDe3a8abCD0e13e845B8CC704F92482819A8516'

  const body = { kind: TransferKind.Erc20, to: address, amount: '1000000000', contract }

  const challenge = await delegatedClient(req.cookies.DFNS_AUTH_TOKEN).wallets.transferAssetInit({
    walletId,
    body: { kind: TransferKind.Erc20, to: address, amount: '1000000000', contract },
  })

  res.json({ address, challenge, walletId, body })
})

app.post('/wallets/erc/complete', async (req: Request, res: Response) => {
  const { signedChallenge, body, walletId } = req.body

  const trx = await delegatedClient(req.cookies.DFNS_AUTH_TOKEN).wallets.transferAssetComplete(
    {
      walletId,
      body,
    },
    signedChallenge
  )

  res.send(trx)
})

app.post(
  '/wallets/new/complete',
  asyncHandler(async (req: Request, res: Response) => {
    // use the original request body and the signed challenge to complete the action
    const { requestBody, signedChallenge } = req.body
    await delegatedClient(req.cookies.DFNS_AUTH_TOKEN).wallets.createWalletComplete(
      { body: requestBody },
      signedChallenge
    )

    // perform any local system updates with the DFNS response

    res.status(204).end()
  })
)

app.post(
  '/wallet/recover',
  asyncHandler(async (req: Request, res: Response) => {
    const client = apiClient()
  })
)

const port = process.env.PORT
app.listen(port, () => {
  console.log(`⚡️[server]: Server is running at http://localhost:${port}`)
})

////////////////////////////////////////////////////////////////
// function arrayBufferToBase64(buffer: any) {
//   const bytes = new Uint8Array(buffer)
//   return btoa(String.fromCharCode(...bytes))
// }

// function arrayBufferToBase64Url(buffer: any) {
//   return arrayBufferToBase64(buffer).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
// }

// function arrayBufferToHex(buffer: any) {
//   const bytes = new Uint8Array(buffer)
//   return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, '0')).join('')
// }

// function base64ToArrayBuffer(base64: any) {
//   const binary = atob(base64)
//   const bytes = new Uint8Array(binary.length)
//   for (let i = 0; i < binary.length; i++) {
//     bytes[i] = binary.charCodeAt(i)
//   }
//   return bytes.buffer
// }

// async function usernameToSalt(username: any) {
//   const normalizedUsername = username.toLowerCase().trim()
//   const usernameHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(normalizedUsername))
//   return new Uint8Array(usernameHash)
// }

// function minimizeBigInt(value: any) {
//   if (value.length === 0) {
//     return value
//   }
//   const minValue = [0, ...value]
//   for (let i = 0; i < minValue.length; ++i) {
//     if (minValue[i] === 0) {
//       continue
//     }
//     if (minValue[i] > 0x7f) {
//       return minValue.slice(i - 1)
//     }
//     return minValue.slice(i)
//   }
//   return new Uint8Array([0])
// }

// function rawSignatureToAns1(rawSignature: any) {
//   if (rawSignature.length !== 64) {
//     console.log(rawSignature.length)
//     return new Uint8Array([0])
//   }
//   const r = rawSignature.slice(0, 32)
//   const s = rawSignature.slice(32)

//   const minR = minimizeBigInt(r)
//   const minS = minimizeBigInt(s)

//   return new Uint8Array([0x30, minR.length + minS.length + 4, 0x02, minR.length, ...minR, 0x02, minS.length, ...minS])
// }

// async function generateSignature(
//   encryptedPrivateKey: any,
//   message: any,
//   password: any,
//   username: any,
//   encoding = 'hex'
// ) {
//   const salt = await usernameToSalt(username)
//   const { key: base64Key, iv: base64Iv } = JSON.parse(atob(encryptedPrivateKey))
//   const iv = base64ToArrayBuffer(base64Iv)
//   const key = base64ToArrayBuffer(base64Key)

//   const keyMaterial = await crypto.subtle.importKey(
//     'raw',
//     new TextEncoder().encode(password),
//     { name: 'PBKDF2' },
//     false,
//     ['deriveBits', 'deriveKey']
//   )
//   const unwrappingKey = await crypto.subtle.deriveKey(
//     {
//       name: 'PBKDF2',
//       salt: salt,
//       iterations: 100000,
//       hash: 'SHA-256',
//     },
//     keyMaterial,
//     { name: 'AES-GCM', length: 256 },
//     true,
//     ['wrapKey', 'unwrapKey']
//   )

//   const privateKey = await crypto.subtle.unwrapKey(
//     'pkcs8',
//     key,
//     unwrappingKey,
//     {
//       name: 'AES-GCM',
//       iv: iv,
//     },
//     { name: 'ECDSA', namedCurve: 'P-256' },
//     true,
//     ['sign']
//   )

//   const signature = await crypto.subtle.sign(
//     { name: 'ECDSA', hash: { name: 'SHA-256' } },
//     privateKey,
//     new TextEncoder().encode(message)
//   )

//   if (encoding === 'hex') {
//     return arrayBufferToHex(rawSignatureToAns1(new Uint8Array(signature)))
//   } else if (encoding === 'base64url') {
//     return arrayBufferToBase64Url(rawSignatureToAns1(new Uint8Array(signature)))
//   }
//   throw new Error('encoding not supported.')
// }

// async function exportPublicKeyInPemFormat(key: any) {
//   const exported = await crypto.subtle.exportKey('spki', key)
//   const pem = `-----BEGIN PUBLIC KEY-----\n${arrayBufferToBase64(exported)}\n-----END PUBLIC KEY-----`
//   return pem
// }

// async function generateEncryptedPrivateKeyAndPublicKey(password: any, username: any) {
//   const salt = await usernameToSalt(username)
//   const iv = crypto.getRandomValues(new Uint8Array(16))

//   const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])

//   const keyMaterial = await crypto.subtle.importKey(
//     'raw',
//     new TextEncoder().encode(password),
//     { name: 'PBKDF2' },
//     false,
//     ['deriveBits', 'deriveKey']
//   )

//   const wrappingKey = await crypto.subtle.deriveKey(
//     {
//       name: 'PBKDF2',
//       salt,
//       iterations: 100000,
//       hash: 'SHA-256',
//     },
//     keyMaterial,
//     { name: 'AES-GCM', length: 256 },
//     true,
//     ['wrapKey', 'unwrapKey']
//   )

//   const encryptedPrivateKey = await crypto.subtle.wrapKey('pkcs8', keyPair.privateKey, wrappingKey, {
//     name: 'AES-GCM',
//     iv,
//   })
//   const pemPublicKey = await exportPublicKeyInPemFormat(keyPair.publicKey)

//   const privateKey = btoa(
//     JSON.stringify({
//       key: arrayBufferToBase64(encryptedPrivateKey),
//       iv: arrayBufferToBase64(iv),
//     })
//   )

//   return {
//     encryptedPrivateKey: privateKey,
//     pemPublicKey: pemPublicKey,
//   }
// }

// const generateRecoveryKey = () => {
//   const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
//   const uuid1 = crypto.randomUUID().replace(/-/g, '')
//   const uuid2 = crypto.randomUUID().replace(/-/g, '')

//   let password = ''
//   for (let i = 0; i < uuid1.length; ++i) {
//     const key = parseInt(uuid1[i], 16) + (parseInt(uuid2[i]) < 8 ? 0 : 16)
//     password += alphabet[key]
//   }
//   return (
//     'D1-' +
//     password.substring(0, 6) +
//     '-' +
//     password.substring(6, 11) +
//     '-' +
//     password.substring(11, 16) +
//     '-' +
//     password.substring(16, 21) +
//     '-' +
//     password.substring(21, 26) +
//     '-' +
//     password.substring(26)
//   )
// }

// const generateRecoveryKeyCredential = async (username: any, clientData: any) => {
//   const recoveryKey = generateRecoveryKey()
//   const { encryptedPrivateKey, pemPublicKey } = await generateEncryptedPrivateKeyAndPublicKey(recoveryKey, username)

//   const clientDataHash = arrayBufferToHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(clientData)))
//   const signature = await generateSignature(
//     encryptedPrivateKey,
//     JSON.stringify({
//       clientDataHash: clientDataHash,
//       publicKey: pemPublicKey,
//     }),
//     recoveryKey,
//     username
//   )

//   const attestationData = JSON.stringify({
//     publicKey: pemPublicKey,
//     signature: signature,
//     algorithm: 'SHA256',
//   })

//   const privateKeyHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(encryptedPrivateKey))

//   // self.postMessage({
//   //   type: 'encryptedPrivateKeyAndPublicKey',
//   //   encryptedPrivateKey,
//   //   attestationData,
//   //   recoveryKey,
//   //   credentialId: arrayBufferToBase64Url(privateKeyHash),
//   // })
// }

// self.addEventListener('message', async (event) => {
//   try {
//     switch (event.data.type) {
//       case 'generateEncryptedPrivateKeyAndPublicKey': {
//         const { username, clientData } = event.data
//         await generateRecoveryKeyCredential(username, clientData)
//         break
//       }
//       case 'generateSignature': {
//         const { encryptedPrivateKey, message, recoveryKey, username } = event.data
//         const signature = await generateSignature(encryptedPrivateKey, message, recoveryKey, username, 'base64url')
//         self.postMessage({
//           type: 'signature',
//           signature,
//         })
//         break
//       }
//       case 'validateRecoveryKey': {
//         const { encryptedPrivateKey, recoveryKey, username } = event.data
//         const message = crypto.getRandomValues(new Uint8Array(64))
//         await generateSignature(encryptedPrivateKey, message, recoveryKey, username)
//         self.postMessage({
//           type: 'recoveryKeyIsValid',
//         })
//         break
//       }
//     }
//   } catch (e) {
//     self.postMessage({
//       type: 'error',
//       error: e,
//     })
//   }
// })
