// FIXME: Unable to import package
// import AccessController from 'orbit-db-access-controllers/interface'
import OrbitDB from 'orbit-db'
import * as Block from 'multiformats/block'
import * as dagCbor from '@ipld/dag-cbor'
import { sha256 } from 'multiformats/hashes/sha2'
import { getCrypto } from 'pkijs'
import { stringToArrayBuffer } from 'pvutils'
import { keyObjectFromString, verifyDataSignature } from '@quiet/identity'
import { UserProfile, NoCryptoEngineError } from '@quiet/types'
import Logger from '../common/logger'

const type = 'userProfilesAccess'

// FIXME: Should implement AccessController
export class UserProfilesAccessController {
  private readonly crypto = getCrypto()
  private readonly codec = dagCbor
  private readonly hasher = sha256
  private readonly logger = Logger(UserProfilesAccessController.name)

  static get type() {
    return type
  }

  /**
   * Users can only append if the entry key (their cert public key)
   * matches the user profile signature. This prevents someone from
   * appending a user profile that isn't theirs.
   */
  async canAppend(entry: LogEntry<UserProfile>) {
    if (!this.crypto) throw new NoCryptoEngineError()

    let verify = false

    try {
      if (entry.payload.key !== entry.payload.value.pubKey) {
        return false
      }

      const pubKey = await keyObjectFromString(entry.payload.key, this.crypto)
      const profile = entry.payload.value.profile
      const profileSig = stringToArrayBuffer(entry.payload.value.profileSig)
      const { bytes } = await Block.encode({ value: profile, codec: this.codec, hasher: this.hasher })
      verify = await verifyDataSignature(profileSig, bytes, pubKey)
    } catch (err) {
      this.logger('ERROR: Failed to verify user profile', err)
    }

    this.logger('Entry verified', entry.payload, verify)

    return verify
  }

  async save() {
    return ''
  }

  async load() {
    return ''
  }

  static async create(orbitdb: OrbitDB, options = {}) {
    return new UserProfilesAccessController()
  }
}
