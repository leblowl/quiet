import { type Socket, applyEmitParams } from '../../../types'
import { type PayloadAction } from '@reduxjs/toolkit'
import { signData, loadPrivateKey, pubKeyFromCsr } from '@quiet/identity'
import { call, select, apply, put } from 'typed-redux-saga'
import { arrayBufferToString } from 'pvutils'
import { config } from '../../users/const/certFieldTypes'
import { identitySelectors } from '../../identity/identity.selectors'
import { usersActions } from '../users.slice'
import { UserProfile, UserProfileData, SocketActionTypes } from '@quiet/types'
import * as Block from 'multiformats/block'
import * as dagCbor from '@ipld/dag-cbor'
import { sha256 } from 'multiformats/hashes/sha2'

export function* saveUserProfileSaga(
  socket: Socket,
  action: PayloadAction<UserProfileData>
): Generator {
  const identity = yield* select(identitySelectors.currentIdentity)

  if (!identity?.userCsr) {
    return
  }

  const codec = dagCbor
  const hasher = sha256
  const { bytes } = yield* call(Block.encode, { value: action.payload, codec: codec, hasher: hasher })
  const keyObject = yield* call(loadPrivateKey, identity.userCsr.userKey, config.signAlg)
  const signatureArrayBuffer = yield* call(signData, bytes, keyObject)
  const signature = yield* call(arrayBufferToString, signatureArrayBuffer)
  const pubKey = yield* call(pubKeyFromCsr, identity.userCsr.userCsr)

  const userProfile: UserProfile = {
    profile: action.payload,
    profileSig: signature,
    pubKey,
  }

  console.log("Saving user profile", userProfile)

  yield* apply(
    socket,
    socket.emit,
    applyEmitParams(SocketActionTypes.SAVE_USER_PROFILE, userProfile),
  )
}
