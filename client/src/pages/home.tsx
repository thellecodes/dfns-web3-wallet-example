import { PaginatedWalletList } from '@dfns/sdk/codegen/datamodel/Wallets'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import '../globals.css'
import { api } from '../api'
import useAuth from '../hooks/useAuth'

export default function Home(): JSX.Element {
  const { user, logout } = useAuth()
  const [wallets, setWallets] = useState<PaginatedWalletList | undefined>(undefined)
  const [walletAssets, setWalletAssets] = useState<any>(null)
  const [toAddress, setToAddress] = useState('')

  useEffect(() => {
    api.listWallets().then((wallets) => {
      setWallets(wallets)
      if (wallets?.items) {
        api.geWalletAssets(wallets).then((assets: any) => {
          const keys = Object.keys(assets)
          const toArr = keys.map((key: any, index: any) => ({
            key: assets[key],
          }))

          setWalletAssets(toArr)
        })
      }
    })
  }, [])

  const onSend = () => {
    // api.sendNativeToAddress(toAddress).then((ev: any) => ev)
    api.sendERCToken(toAddress).then((ev: any) => ev)
  }

  const onGenSig = () => {
    api.onGenSig().then((a) => a)
  }

  return (
    <div>
      <>
        <div className="flex items-center gap-2">
          <p className="text-2x">Hello {user}</p>

          <button className="btn" type="button" onClick={logout}>
            Logout
          </button>
        </div>
        <table className="w-full">
          <thead>
            <tr>
              <th>Network</th>
              <th>Address</th>
            </tr>
          </thead>
          <tbody>
            {wallets?.items &&
              wallets.items.map((wallet) => (
                <tr key={wallet.id}>
                  <td>{wallet.network}</td>
                  <td>{wallet.address}</td>
                  <>{console.log(wallet.id)}</>
                </tr>
              ))}
          </tbody>
          <tfoot>
            <tr>
              <td colSpan={3}>
                <Link className="btn" to="/wallets/new">
                  New Wallet
                </Link>
              </td>
            </tr>
          </tfoot>
        </table>
        {walletAssets &&
          walletAssets.map((wlt: any, index: number) => (
            <table className="w-full">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Amount</th>
                  <th>toAddress</th>
                </tr>
              </thead>
              <tbody>
                {wlt.key.map((w: any) => (
                  <tr>
                    <td>{w.symbol}</td>
                    <td>{w.balance / 10 ** 18}</td>
                    <td>
                      <input value={toAddress} onChange={(e: any) => setToAddress(e.target.value)} />
                    </td>
                    <td>
                      <button className="btn" type="submit" style={{ marginLeft: '1rem' }} onClick={onSend}>
                        Send
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
              <tfoot>
                <tr>
                  <td colSpan={3}>
                    <h2>{wlt.key[0].symbol} Assets</h2>
                  </td>
                </tr>
              </tfoot>
            </table>
          ))}

        <button className="btn" type="submit" style={{ marginLeft: '1rem' }} onClick={onGenSig}>
          Generate Signature and Send trx
        </button>
      </>
    </div>
  )
}
