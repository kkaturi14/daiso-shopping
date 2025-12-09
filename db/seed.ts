import { cwd } from 'node:process'
import { loadEnvConfig } from '@next/env'

import { drizzle } from 'drizzle-orm/node-postgres'
import { Client } from 'pg'

import * as schema from './schema'
import sampleData from '@/lib/sample-data'

loadEnvConfig(cwd())

const main = async () => {
  try {
    console.log('Connecting to database...')
    const client = new Client({
      connectionString: process.env.POSTGRES_URL,
    })
    await client.connect()
    console.log('Connected!')
    const db = drizzle(client, { schema })

    await db.delete(schema.products)
    await db.delete(schema.accounts)
    await db.delete(schema.users)

    const resUsers = await db
      .insert(schema.users)
      .values(sampleData.users)
      .returning()

    const resProducts = await db
      .insert(schema.products)
      .values(sampleData.products)
      .returning()
    console.log({ resUsers, resProducts })
    await client.end()
  } catch (error) {
    console.error(error)
    throw new Error('Failed to seed database')
  }
}

main()
