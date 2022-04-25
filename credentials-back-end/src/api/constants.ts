export const HEADERS = {
    json: { 'Content-Type': 'application/json' },
    text: { 'Content-Type': 'text/plain' },
}

export const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,OPTIONS',
    'Access-Control-Max-Age': '86400'
}

export const DEFAULT_CONFIG = `
version: 3.0

constants:
  baseUrl: http://localhost:3332
  port: 3332
  # please use your own X25519 key, this is only an example
  # you can generate a new key by running \`veramo config gen-key\` in a terminal
  dbEncryptionKey: 29739248cad1bd1a0fc4d9b75cd4d2990de535baf5caadfdf8d8f86664aa830c
  databaseFile: ./database.sqlite
  methods:
    - keyManagerGetKeyManagementSystems
    - keyManagerCreate
    - keyManagerGet
    - keyManagerDelete
    - keyManagerImport
    - keyManagerEncryptJWE
    - keyManagerDecryptJWE
    - keyManagerSign
    - keyManagerSharedSecret
    - keyManagerSignJWT
    - keyManagerSignEthTX
    - didManagerGetProviders
    - didManagerFind
    - didManagerGet
    - didManagerCreate
    - didManagerGetOrCreate
    - didManagerImport
    - didManagerDelete
    - didManagerAddKey
    - didManagerRemoveKey
    - didManagerAddService
    - didManagerRemoveService
    - resolveDid
    - getDIDComponentById
    - discoverDid
    - dataStoreGetMessage
    - dataStoreSaveMessage
    - dataStoreGetVerifiableCredential
    - dataStoreSaveVerifiableCredential
    - dataStoreGetVerifiablePresentation
    - dataStoreSaveVerifiablePresentation
    - dataStoreORMGetIdentifiers
    - dataStoreORMGetIdentifiersCount
    - dataStoreORMGetMessages
    - dataStoreORMGetMessagesCount
    - dataStoreORMGetVerifiableCredentialsByClaims
    - dataStoreORMGetVerifiableCredentialsByClaimsCount
    - dataStoreORMGetVerifiableCredentials
    - dataStoreORMGetVerifiableCredentialsCount
    - dataStoreORMGetVerifiablePresentations
    - dataStoreORMGetVerifiablePresentationsCount
    - handleMessage
    - packDIDCommMessage
    - unpackDIDCommMessage
    - sendDIDCommMessage
    - sendMessageDIDCommAlpha1
    - createVerifiablePresentation
    - createVerifiableCredential
    - createSelectiveDisclosureRequest
    - getVerifiableCredentialsForSdr
    - validatePresentationAgainstSdr

# Data base
dbConnection:
  $require: typeorm?t=function#createConnection
  $args:
    - type: sqlite
      database:
        $ref: /constants/databaseFile
      synchronize: false
      migrationsRun: true
      migrations:
        $require: '@veramo/data-store?t=object#migrations'
      logging: false
      entities:
        $require: '@veramo/data-store?t=object#Entities'

# Server configuration
server:
  baseUrl:
    $ref: /constants/baseUrl
  port:
    $ref: /constants/port
  use:
    # CORS
    - - $require: 'cors'

    # Add agent to the request object
    - - $require: '@veramo/remote-server?t=function#RequestWithAgentRouter'
        $args:
          - agent:
              $ref: /agent

    # DID Documents
    - - $require: '@veramo/remote-server?t=function#WebDidDocRouter'

    # API base path
    - - /messaging
      - $require: '@veramo/remote-server?t=function#MessagingRouter'
        $args:
          - metaData:
              type: DIDComm
              value: https

    # API base path
    - - /agent
      - $require: '@veramo/remote-server?t=function#apiKeyAuth'
        $args:
          - apiKey: test123
      - $require: '@veramo/remote-server?t=function#AgentRouter'
        $args:
          - exposedMethods:
              $ref: /constants/methods

    # Open API schema
    - - /open-api.json
      - $require: '@veramo/remote-server?t=function#ApiSchemaRouter'
        $args:
          - basePath: :3332/agent
            securityScheme: bearer
            apiName: Agent
            apiVersion: '1.0.0'
            exposedMethods:
              $ref: /constants/methods

    # Swagger docs
    - - /api-docs
      - $require: swagger-ui-express?t=object#serve
      - $require: swagger-ui-express?t=function#setup
        $args:
          - null
          - swaggerOptions:
              url: '/open-api.json'

  # Execute during server initialization
  init:
    - $require: '@veramo/remote-server?t=function#createDefaultDid'
      $args:
        - agent:
            $ref: /agent
          baseUrl:
            $ref: /constants/baseUrl
          messagingServiceEndpoint: /messaging

# Message handler plugin
messageHandler:
  $require: '@veramo/message-handler#MessageHandler'
  $args:
    - messageHandlers:
        - $require: '@veramo/did-comm#DIDCommMessageHandler'
        - $require: '@veramo/did-jwt#JwtMessageHandler'
        - $require: '@veramo/credential-w3c#W3cMessageHandler'
        - $require: '@veramo/selective-disclosure#SdrMessageHandler'

# DID resolvers
didResolver:
  $require: '@veramo/did-resolver#DIDResolverPlugin'
  $args:
    - resolver:
        $require: did-resolver#Resolver
        $args:
          - ethr:
              $ref: /ethr-did-resolver
            web:
              $ref: /web-did-resolver
            key:
              $ref: /did-key-resolver
            elem:
              $ref: /universal-resolver
            io:
              $ref: /universal-resolver
            ion:
              $ref: /universal-resolver
            sov:
              $ref: /universal-resolver

ethr-did-resolver:
  $require: ethr-did-resolver?t=function&p=/ethr#getResolver
  $args:
    - infuraProjectId: ***REMOVED***

web-did-resolver:
  $require: web-did-resolver?t=function&p=/web#getResolver

universal-resolver:
  $require: '@veramo/did-resolver#UniversalResolver'
  $args:
    - url: https://dev.uniresolver.io/1.0/identifiers/

did-key-resolver:
  $require: '@veramo/did-provider-key?t=function&p=/key#getDidKeyResolver'

# Key Manager
keyManager:
  $require: '@veramo/key-manager#KeyManager'
  $args:
    - store:
        $require: '@veramo/data-store#KeyStore'
        $args:
          - $ref: /dbConnection
      kms:
        local:
          $require: '@veramo/kms-local#KeyManagementSystem'
          $args:
            - $require: '@veramo/data-store#PrivateKeyStore'
              $args:
                - $ref: /dbConnection
                - $require: '@veramo/kms-local#SecretBox'
                  $args:
                    - $ref: /constants/dbEncryptionKey

# DID Manager
didManager:
  $require: '@veramo/did-manager#DIDManager'
  $args:
    - store:
        $require: '@veramo/data-store#DIDStore'
        $args:
          - $ref: /dbConnection
      defaultProvider: did:ethr:rinkeby
      providers:
        did:ethr:
          $require: '@veramo/did-provider-ethr#EthrDIDProvider'
          $args:
            - defaultKms: local
              network: mainnet
              rpcUrl: https://mainnet.infura.io/v3/***REMOVED***
              gas: 1000001
              ttl: 31104001
        did:ethr:rinkeby:
          $require: '@veramo/did-provider-ethr#EthrDIDProvider'
          $args:
            - defaultKms: local
              network: rinkeby
              rpcUrl: https://rinkeby.infura.io/v3/***REMOVED***
              gas: 1000001
              ttl: 31104001
        did:ethr:ropsten:
          $require: '@veramo/did-provider-ethr#EthrDIDProvider'
          $args:
            - defaultKms: local
              network: ropsten
              rpcUrl: https://ropsten.infura.io/v3/***REMOVED***
              gas: 1000001
              ttl: 31104001
        did:ethr:kovan:
          $require: '@veramo/did-provider-ethr#EthrDIDProvider'
          $args:
            - defaultKms: local
              network: kovan
              rpcUrl: https://kovan.infura.io/v3/***REMOVED***
              gas: 1000001
              ttl: 31104001
        did:ethr:goerli:
          $require: '@veramo/did-provider-ethr#EthrDIDProvider'
          $args:
            - defaultKms: local
              network: goerli
              rpcUrl: https://goerli.infura.io/v3/***REMOVED***
              gas: 1000001
              ttl: 31104001
        did:web:
          $require: '@veramo/did-provider-web#WebDIDProvider'
          $args:
            - defaultKms: local
        did:key:
          $require: '@veramo/did-provider-key#KeyDIDProvider'
          $args:
            - defaultKms: local

didDiscovery:
  $require: '@veramo/did-discovery#DIDDiscovery'
  $args:
    - providers:
        - $require: '@veramo/did-manager#AliasDiscoveryProvider'
        - $require: '@veramo/data-store#ProfileDiscoveryProvider'

# Agent
agent:
  $require: '@veramo/core#Agent'
  $args:
    - schemaValidation: false
      plugins:
        - $ref: /keyManager
        - $ref: /didManager
        - $ref: /didResolver
        - $ref: /didDiscovery
        - $ref: /messageHandler
        - $require: '@veramo/did-comm#DIDComm'
        - $require: '@veramo/credential-w3c#CredentialIssuer'
        - $require: '@veramo/selective-disclosure#SelectiveDisclosure'
        - $require: '@veramo/data-store#DataStore'
          $args:
            - $ref: /dbConnection
        - $require: '@veramo/data-store#DataStoreORM'
          $args:
            - $ref: /dbConnection
`

export const INFURA_PROJECT_ID = '***REMOVED***'

export const KMS_SECRET_KEY = '***REMOVED***'

export const ISSUER_ID = 'did:ethr:rinkeby:0x97fd27892cdcD035dAe1fe71235c636044B59348'

export const VC_CONTEXT = ['https://www.w3.org/2018/credentials/v1', 'https://veramo.io/contexts/profile/v1']

export const VC_TYPE = 'VerifiableCredential'

export const VC_SUBJECT = 'did:ethr:ropsten:0x0320ece5f7c4f59ee1f2ece0b24760f17b959a10387b7346aebd571a17395bd302'

export const VC_PROOF_FORMAT = 'jwt'

// Auth
export const PROPOSAL_MESSAGE_TITLE = 'AuthRequest'

export const REPLY_PROTECTION_INTERVAL = 30