import { combineReducers } from '@reduxjs/toolkit'
import { expectSaga } from 'redux-saga-test-plan'
import { call } from 'redux-saga-test-plan/matchers'
import { setupCrypto } from '@quiet/identity'
import { prepareStore } from '../../../utils/tests/prepareStore'
import { communitiesActions, Community } from '../communities.slice'
import { NetworkData } from '../communities.types'
import { reducers } from '../../reducers'
import { generateDmKeyPair } from '../../../utils/cryptography/cryptography'
import { responseCreateNetworkSaga } from './responseCreateNetwork.saga'
import { publicChannelsActions } from '../../publicChannels/publicChannels.slice'
import { identityActions } from '../../identity/identity.slice'
import { DmKeys, Identity } from '../../identity/identity.types'

describe('responseCreateNetwork', () => {
  it('create network for joining user', async () => {
    setupCrypto()
    const store = prepareStore().store

    const community: Community = {
      id: '1',
      name: undefined,
      registrarUrl: 'registrarUrl',
      CA: null,
      rootCa: undefined,
      peerList: [],
      registrar: null,
      onionAddress: '',
      privateKey: '',
      port: 0,
      registrationAttempts: 0
    }

    const dmKeys: DmKeys = {
      publicKey: 'publicKey',
      privateKey: 'privateKey'
    }

    const network: NetworkData = {
      hiddenService: {
        onionAddress: 'onionAddress',
        privateKey: 'privateKey'
      },
      peerId: {
        id: 'peerId'
      }
    }

    const identity: Identity = {
      id: community.id,
      nickname: '',
      hiddenService: network.hiddenService,
      peerId: network.peerId,
      dmKeys: dmKeys,
      userCsr: null,
      userCertificate: null
    }

    const reducer = combineReducers(reducers)
    await expectSaga(
      responseCreateNetworkSaga,
      communitiesActions.responseCreateNetwork({
        community: community,
        network: network
      })
    )
      .withReducer(reducer)
      .withState(store.getState())
      .provide([[call.fn(generateDmKeyPair), dmKeys]])
      .call(generateDmKeyPair)
      .put(communitiesActions.addNewCommunity(community))
      .put(communitiesActions.setCurrentCommunity(community.id))
      .put(
        publicChannelsActions.addPublicChannelsList({
          id: community.id
        })
      )
      .put(identityActions.addNewIdentity(identity))
      .run()
  })
})
