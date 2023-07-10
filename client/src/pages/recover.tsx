import React, { FormEvent } from 'react'
import { Link, useLocation } from 'react-router-dom'

import '../globals.css'
import useAuth from '../hooks/useAuth'

export default function Recover(): JSX.Element {
  const { loading, error, recover } = useAuth()
  const location = useLocation()

  const handleRecover = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    const formData = new FormData(event.currentTarget)

    recover(formData.get('username') as string)
  }

  return (
    <form onSubmit={handleRecover}>
      <div className="w-full">
        <h1 className="text-2x">Recover</h1>

        <div className="flex items-center gap-2">
          <input
            className="input"
            id="username"
            name="username"
            placeholder="username"
            value={location.state?.username}
          />

          <button className="btn" disabled={loading} type="submit">
            Submit
          </button>
        </div>

        <div className="flex items-center gap-2 mt">
          or{' '}
          <Link className="btn" to="/login">
            Login
          </Link>
        </div>

        {!!error && <div className="text-red-700">{error.message}</div>}
      </div>
    </form>
  )
}
