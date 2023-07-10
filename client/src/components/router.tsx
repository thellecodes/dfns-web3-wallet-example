import React from 'react'
import { Route, Routes, Navigate, Outlet } from 'react-router-dom'

import useAuth from '../hooks/useAuth'
import Login from '../pages/login'
import Home from '../pages/home'
import Register from '../pages/register'
import WalletNew from '../pages/wallet'
import Recover from '../pages/recover'

function AuthenticatedRoute() {
  const { user } = useAuth()
  if (!user) return <Navigate to="/login" replace={true} />
  return <Outlet />
}

export default function Router(): JSX.Element {
  return (
    <Routes>
      <Route path="/" element={<AuthenticatedRoute />}>
        <Route path="/" element={<Home />} />
      </Route>
      <Route path="/wallets/new" element={<AuthenticatedRoute />}>
        <Route path="/wallets/new" element={<WalletNew />} />
      </Route>
      <Route path="/login" element={<Login />} />
      <Route path="/recover" element={<Recover />} />
      <Route path="/register" element={<Register />} />
    </Routes>
  )
}
