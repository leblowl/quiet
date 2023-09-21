export interface UserData {
  username: string
  onionAddress: string
  peerId: string
  dmPublicKey: string
}

export interface User extends UserData {
  isRegistered: boolean
  isDuplicated: boolean
  pubKey: string
}

export interface UserProfileData {
  photo: string
}

export interface UserProfile {
  profile: UserProfileData
  profileSig: string
  pubKey: string
}

export interface UserProfilesLoadedEvent {
  profiles: UserProfile[]
}

export interface SendCertificatesResponse {
  certificates: string[]
}

export interface SendCsrsResponse {
  csrs: string[]
}
