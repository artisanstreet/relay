// Minimal ambient declarations for the untyped `noise-handshake` dependency.
// Hand-written against noise-handshake@4.2.0 source (noise.js, cipher.js,
// dh.js, symmetric-state.js); covers only the surface this repo uses.
// If the library changes shape, `tsc` + the interop tests fail loudly.

declare module "noise-handshake" {
  export interface NoiseKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  }
  export interface NoiseCurve {
    DHLEN: number;
    PKLEN: number;
    SKLEN: number;
    ALG: string;
    generateKeyPair(privKey?: Uint8Array): NoiseKeyPair;
    dh(publicKey: Uint8Array, keypair: NoiseKeyPair): Uint8Array;
  }
  export interface NoiseOpts {
    curve?: NoiseCurve;
    psk?: Uint8Array;
  }
  export default class NoiseState {
    constructor(pattern: "XX", initiator: boolean, staticKeypair?: NoiseKeyPair, opts?: NoiseOpts);
    initialise(prologue: Uint8Array, remoteStatic?: Uint8Array): void;
    send(payload?: Uint8Array): Uint8Array;
    recv(buf: Uint8Array): Uint8Array;
    complete: boolean;
    tx: Uint8Array | null;
    rx: Uint8Array | null;
    /** 64-byte handshake hash, set on completion. */
    hash: Uint8Array | null;
    /** Remote static public key (32B), set once received. */
    rs: Uint8Array | null;
  }
}

declare module "noise-handshake/cipher" {
  export default class CipherState {
    constructor(key?: Uint8Array | null);
    initialiseKey(key: Uint8Array): void;
    setNonce(nonce: number): void;
    encrypt(plaintext: Uint8Array, ad?: Uint8Array): Uint8Array;
    decrypt(ciphertext: Uint8Array, ad?: Uint8Array): Uint8Array;
    readonly hasKey: boolean;
    nonce: number;
  }
}

declare module "noise-handshake/dh" {
  import type { NoiseCurve } from "noise-handshake";
  export function generateSeedKeyPair(seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  const curve: NoiseCurve;
  export default curve;
}
