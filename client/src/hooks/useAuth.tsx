import React, { createContext, ReactNode, useContext, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { api } from '../api'

export interface AuthContextType {
  loading: boolean
  user?: string
  error?: any
  login: (username: string, password: string) => void
  logout: () => void
  register: (username: string, password: string) => void
  recover: (username: string) => void
}

const AuthContext = createContext<AuthContextType>({} as AuthContextType)

export const AuthProvider = ({ children }: { children: ReactNode }): React.JSX.Element => {
  const [loading, setLoading] = useState<boolean>(false)
  const [user, setUser] = useState<string | undefined>('sam')
  const [error, setError] = useState<any>()
  const navigate = useNavigate()

  const login = (username: string, password: string) => {
    setLoading(true)

    api
      .login(username, password)
      .then(({ username }) => {
        setUser(username)
        navigate('/')
      })
      .catch((err) => setError(err))
      .finally(() => setLoading(false))
  }

  const register = (username: string, password: string) => {
    setLoading(true)

    api
      .register(username, password)
      .then(({ username }) => {
        console.log(username)
        navigate('/login', { state: { username } })
      })
      .catch((err) => setError(err))
      .finally(() => setLoading(false))
  }

  const logout = () => {
    setUser(undefined)
  }

  const recover = (username: string) => {
    api
      .recoverWalletWithUsername(username)
      .then((rv: any) => rv)
      .catch((err) => setError(err))
  }

  return (
    <AuthContext.Provider value={{ loading, user, error, login, logout, register, recover }}>
      {children}
    </AuthContext.Provider>
  )
}

export default function useAuth(): AuthContextType {
  return useContext(AuthContext)
}
