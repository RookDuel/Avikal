/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Atharva Sen Barai.
 */

import {
  Buffer,
  defaultChainInfo,
  defaultChainUrl,
  mainnetClient,
  roundAt,
  roundTime,
  timelockDecrypt,
  timelockEncrypt,
} from 'tlock-js'

function readStdin() {
  return new Promise((resolve, reject) => {
    let input = ''
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', chunk => {
      input += chunk
    })
    process.stdin.on('end', () => resolve(input))
    process.stdin.on('error', reject)
  })
}

function firstRoundAtOrAfter(targetTimeMs) {
  let round = roundAt(targetTimeMs, defaultChainInfo)
  if (roundTime(defaultChainInfo, round) < targetTimeMs) {
    round += 1
  }
  return round
}

function pinnedEncryptionClient() {
  return {
    chain() {
      return {
        async info() {
          return defaultChainInfo
        },
      }
    },
  }
}

async function seal(payload) {
  const unlockTimestamp = Number(payload.unlock_timestamp)
  if (!Number.isFinite(unlockTimestamp) || unlockTimestamp <= 0) {
    throw new Error('Invalid unlock timestamp for drand timelock')
  }

  const keyMaterial = payload.key_b_base64
  if (typeof keyMaterial !== 'string' || !keyMaterial) {
    throw new Error('Missing Key B material for drand timelock')
  }

  const targetTimeMs = unlockTimestamp * 1000
  const round = firstRoundAtOrAfter(targetTimeMs)
  const client = pinnedEncryptionClient()
  const ciphertext = await timelockEncrypt(round, Buffer.from(keyMaterial, 'utf8'), client)

  return {
    success: true,
    provider: 'drand',
    round,
    round_unlock_iso: new Date(roundTime(defaultChainInfo, round)).toISOString(),
    chain_hash: defaultChainInfo.hash,
    chain_url: defaultChainUrl,
    beacon_id: defaultChainInfo.metadata?.beaconID || 'quicknet',
    period_seconds: defaultChainInfo.period,
    ciphertext,
  }
}

async function open(payload) {
  const ciphertext = payload.ciphertext
  const round = Number(payload.round)

  if (typeof ciphertext !== 'string' || !ciphertext) {
    throw new Error('Missing drand ciphertext')
  }
  if (!Number.isFinite(round) || round <= 0) {
    throw new Error('Missing drand target round')
  }

  const client = mainnetClient()
  const latest = await client.latest()

  if (latest.round < round) {
    return {
      success: false,
      status: 'locked',
      provider: 'drand',
      current_round: latest.round,
      required_round: round,
      unlock_iso: new Date(roundTime(defaultChainInfo, round)).toISOString(),
    }
  }

  const originalConsoleLog = console.log
  console.log = () => {}
  let decrypted
  try {
    decrypted = await timelockDecrypt(ciphertext, client)
  } finally {
    console.log = originalConsoleLog
  }
  return {
    success: true,
    provider: 'drand',
    key_b_base64: decrypted.toString('utf8'),
  }
}

async function main() {
  try {
    const raw = await readStdin()
    const payload = JSON.parse(raw || '{}')

    let result
    if (payload.action === 'seal') {
      result = await seal(payload)
    } else if (payload.action === 'open') {
      result = await open(payload)
    } else {
      throw new Error('Unsupported drand helper action')
    }

    process.stdout.write(JSON.stringify(result))
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    process.stdout.write(JSON.stringify({ success: false, error: message }))
    process.exit(1)
  }
}

main()
