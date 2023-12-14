import {
  create_proof,
  setup_generic_prover_and_verifier,
  verify_proof,
} from '@noir-lang/barretenberg/dest/client_proofs';
import { pedersen_from_hex, pedersen_from_dec } from "pedersen-fast";
import { BarretenbergWasm } from '@noir-lang/barretenberg/dest/wasm';
import { SinglePedersen } from "@noir-lang/barretenberg/dest/crypto";


// const createPedersonHash = async () => {
//   const barretenberg = await BarretenbergWasm.new();
//   const pedersen = new SinglePedersen(barretenberg);

//   const stampBuffer = pedersen.compressInputs([Buffer.from(provider), Buffer.from(stampHash)]);

//   const hash = await pedersen.hashToTree([Buffer.from(provider), Buffer.from(stampHash)]);

//   console.log({ stampBuffer, hash });
// };


// createPedersonHash();

// function stringToHex(input: string) {
//   return Array.from(input).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
// }

// const myString = "Hello, world!";
// const hexString = stringToHex(myString);

// pedersen_from_hex(hexString);

// console.log("Hex:", hexString);



// returns a hex string starting with 0x
// const pedersonHash = pedersen_from_hex(
//   "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcde",
//   "0x11223344556677889900aabbccddeeff11223344556677889900aabbccddeef"
// );

// console.log({ pedersonHash });


import { privateKeyToAccount } from 'viem/accounts'
import { createWalletClient, fromBytes, fromHex, http, toBytes } from 'viem';
import { mainnet } from 'viem/chains'


function stringToBytesAndBits(input: string) {
  // Convert the string to bytes
  const bytes = [];
  for (let i = 0; i < input.length; i++) {
      bytes.push(input.charCodeAt(i));
  }

  // Convert bytes to bits
  const bits = bytes.map(byte => {
      return byte.toString(2).padStart(8, '0');
  });

  return {
      bytes: bytes,
      bits: bits.join(' ')
  };
}

const inputString = "Hello";
const result = stringToBytesAndBits(inputString);

console.log("Bytes:", result.bytes);
console.log("Bits:", result.bits);



const privateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
// Local Account
export const account = privateKeyToAccount(privateKey)


export const iamWallet = createWalletClient({
  chain: mainnet,
  transport: http('https://arb-mainnet.g.alchemy.com/v2/os3wVBxfjvmhB8K5iiPf-KKrIf-GgL1r')
})


const provider = "Google";
const stampHash = "v0.0.0:GqmK8ClmCF6E9DaQYe3ei3KGlwyJOWDPNthLX4NRftQ=";
const secret = "secret";

const message = `${provider}:${stampHash}:${secret}`;

const signatureBytes = async (message: string) => {
  const signedMessage = await account.signMessage({message});

  const bytes = fromHex(signedMessage, "bytes");

  return bytes;
};


const formatProofInputs = async (message: string) => {
  const messageBytes = await toBytes(message);
  const messageAndPkBytes = await toBytes(message + privateKey);
  const sigBytes = await signatureBytes(message);

  

  const publicKeyBytes = await toBytes(account.publicKey);

  const public_key_x_coordinates = publicKeyBytes.slice(0, 32);
  const public_key_y_coordinates = publicKeyBytes.slice(32, 64);

  console.log({messageBytes, messageAndPkBytes: JSON.stringify([...messageAndPkBytes]), sigBytes, public_key_x_coordinates, public_key_y_coordinates})


  return {messageBytes, sigBytes};
};

formatProofInputs(message);



// const buildStampInput = (provider: string, stampHash: string, secret: string) => {
//   const input = `${provider}:${stampHash}:${secret}`;

//   return stampBuffer;
// };



// buildStampInput(provider, stampHash);

