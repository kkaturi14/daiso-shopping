import { DrizzleAdapter } from '@auth/drizzle-adapter'
import { compareSync } from 'bcrypt-ts-edge'
import { eq } from 'drizzle-orm'
import type { NextAuthConfig } from 'next-auth'
import NextAuth from 'next-auth'
import CredentialsProvider from 'next-auth/providers/credentials'

import db from './db/drizzle'
import { carts, users } from './db/schema'
import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'

export const config = {
  pages: {
    signIn: '/sign-in',
    error: '/sign-in',
  },
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60,
  },
  adapter: DrizzleAdapter(db),
  providers: [
    CredentialsProvider({
      credentials: {
        email: {
          type: 'email',
        },
        password: { type: 'password' },
      },
      async authorize(credentials) {
        if (credentials == null) return null

        const user = await db.query.users.findFirst({
          where: eq(users.email, credentials.email as string),
        })
        if (user && user.password) {
          const isMatch = compareSync(
            credentials.password as string,
            user.password
          )
          if (isMatch) {
            return {
              id: user.id,
              name: user.name,
              email: user.email,
              role: user.role,
            }
          }
        }
        return null
      },
    }),
  ],
  callbacks: {
    jwt: async ({ token, user, trigger, session }: any) => {
      if (user) {
        if (trigger === 'signIn' || trigger === 'signUp') {
          const sessionCartId = cookies().get('sessionCartId')?.value
          if (!sessionCartId) throw new Error('Session Cart Not Found')
          const sessionCartExists = await db.query.carts.findFirst({
            where: eq(carts.sessionCartId, sessionCartId),
          })
          if (sessionCartExists && !sessionCartExists.userId) {
            const userCartExists = await db.query.carts.findFirst({
              where: eq(carts.userId, user.id),
            })
            if (userCartExists) {
              cookies().set('beforeSigninSessionCartId', sessionCartId)
              cookies().set('sessionCartId', userCartExists.sessionCartId)
            } else {
              await db.update(carts)
                .set({ userId: user.id })
                .where(eq(carts.id, sessionCartExists.id))
                .execute()
            }
          }
        }
      }

      if (session?.user.name && trigger === 'update') {
        token.name = session.user.name
      }
      return token
    },
    session: async ({ session, user, trigger, token }: any) => {
      session.user.id = token.sub
      session.user.role = token.role
      session.user.name = token.name
      if (trigger === 'update') {
        session.user.name = user.name
      }
      return session
    },
    authorized({ request, auth }: any) {
      const protectedPaths = [
        /\/shipping-address/,
        /\/payment-method/,
        /\/place-order/,
        /\/profile/,
        /\/user\/(.*)/,
        /\/order\/(.*)/,
        /\/admin/,
      ]
      const { pathname } = request.nextUrl
      if (!auth && protectedPaths.some((p) => p.test(pathname))) return false
      
      // Ensure sessionCartId cookie exists
      const sessionCartId = request.cookies.get('sessionCartId')?.value
      if (!sessionCartId) {
        const newSessionCartId = crypto.randomUUID()
        const response = NextResponse.next()
        response.cookies.set('sessionCartId', newSessionCartId, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          maxAge: 60 * 60 * 24 * 30, // 30 days
        })
        return response
      }
      return true
    },
  },
} satisfies NextAuthConfig
export const { handlers, auth, signIn, signOut } = NextAuth(config)
