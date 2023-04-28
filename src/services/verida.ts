import { EnvironmentType } from "@verida/types";
import { Context, Network } from "@verida/client-ts";
import { AutoAccount } from "@verida/account-node";
import { Credential } from "../types/types";

const polygonRpcUrl = "https://rpc-mumbai.maticvigil.com";

/** Structure of the record stored on the Verida Network */
interface DataRecord {
  /** Name/Title of the record, for instance used while browsing the UI. Optional. */
  name?: string;
  /** A summary of the data, could be displayed in the UI. Optional. */
  summary?: string;
  /** The schema of the record, For Credential data, it will be the Credential schema. Required. */
  schema: string;
  /** Any specific attributes of the record. These are following the schema mentioned above. */
  [key: string]: unknown;
}

// Schema to store a Verifiable Credential on the Verida Network.
export const VERIDA_CREDENTIAL_RECORD_SCHEMA =
  "https://common.schemas.verida.io/credential/base/v0.2.0/schema.json";

/** Structure of a Credential record stored on the Verida Network. */
interface CredentialDataRecord extends DataRecord {
  /** Name is mandatory */
  name: string;
  /** DID JWT of this credential  */
  didJwtVc: string;
  /** Schema of the DID-JWT Verifiable Credential */
  credentialSchema: string;
  /** Data included in the DID-JWT Verifiable Credential */
  credentialData: object;
}

/**
 * Helper class for the Verida protocol.
 *
 * Run the init method before running any other method.
 */
export class VeridaHelper {
  private context?: Context;
  private account?: AutoAccount;

  /**
   * Initialise the Verida account and context.
   *
   * @param environment The Verida environment.
   * @param contextName The Context name of the application.
   * @param accountPrivateKey The private key of the account
   */
  async init(
    environment: EnvironmentType,
    contextName: string,
    accountPrivateKey: string,
    polygonPrivateKey: string
  ) {
    this.account = new AutoAccount({
      privateKey: accountPrivateKey,
      environment,
      didClientConfig: {
        callType: "web3",
        web3Config: {
          rpcUrl: polygonRpcUrl,
          privateKey: polygonPrivateKey, // Polygon private key for creating DID, not needed in our case but required in the current version of the config.
        },
      },
    });

    this.context = await Network.connect({
      client: {
        environment,
      },
      context: {
        name: contextName,
      },
      account: this.account,
    });
  }

  /**
   * Send data to a DID via the Verida protocol.
   *
   * @param recipientDid The DID of the recipient.
   * @param subject The subject of the message (similar to an email subject).
   * @param data The data to be sent.
   */
  async sendData(recipientDid: string, subject: string, data: DataRecord) {
    if (!this.context) {
      throw new Error(
        "The Verida context doesn't exist, run the 'init' method before using any other methods"
      );
    }

    const messagingClient = await this.context.getMessaging();

    const messageType = "inbox/type/dataSend"; // There are different types of message, here we are sending some data.
    const messageData = {
      data: [data],
    };
    const messageConfig = {
      recipientContextName: "Verida: Vault", // The inbox of a DID is on the 'Verida: Vault' context. This context is the private space of this DID.
      did: recipientDid,
    };

    await messagingClient.send(
      recipientDid,
      messageType,
      messageData,
      subject,
      messageConfig
    );
  }

  /**
   * Send a Verifiable Credential to a DID via the Verida protocol.
   *
   * @param recipientDid  The DID of the recipient.
   * @param messageSubject The subject of the message in which the Credential will be sent to the recipient (similar to an email subject).
   * @param credential The credential itself.
   * @param credentialName The name of the credential. For instance, will be displayed in the Verida Wallet UI.
   * @param credentialSummary A summary of the credential. For instance, will be displayed in the Verida Wallet UI.
   */
  async sendCredential(
    recipientDid: string,
    messageSubject: string,
    credential: Credential,
    credentialName: string,
    credentialSummary?: string
  ) {
    // The Credential record is how Verida wrap the credential to store it on the Network. Check the JSdoc of the type and each property. They are following the Verida Credential Record schema.
    const credentialRecord: CredentialDataRecord = {
      name: credentialName,
      summary: credentialSummary,
      schema: VERIDA_CREDENTIAL_RECORD_SCHEMA,
      didJwtVc: credential.proof.jwt,
      credentialSchema: credential.credentialSchema.id,
      credentialData: credential,
    };
    this.sendData(recipientDid, messageSubject, credentialRecord);
  }
}
