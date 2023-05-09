// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { toB64 } from '@mysten/bcs';
import { SIGNATURE_FLAG_TO_SCHEME, SIGNATURE_SCHEME_TO_FLAG, SerializedSignature, SignatureFlag, SignaturePubkeyPair, fromSerializedSignature } from './signature';
import { PublicKey } from './publickey';
import { blake2b } from '@noble/hashes/blake2b';
import { bytesToHex } from '@noble/hashes/utils';
import RoaringBitmap32 from 'roaring/RoaringBitmap32';

import { normalizeSuiAddress, SUI_ADDRESS_LENGTH } from '../types';
import { Ed25519PublicKey, Secp256k1PublicKey, builder, fromB64 } from '..';
import {
  number,
  object,
  string,
  array,
  tuple,
  Infer,
  integer
} from 'superstruct';

export type PubkeyWeightPair = {
  pubKey: PublicKey;
  weight: number;
};

export const CompressedSignature = object({
  flag: integer(),
  sig: array(integer()),
});
export type CompressedSignature = Infer<typeof CompressedSignature>;

export const MultiSigPublicKey = object({
  pk_map: array(tuple([string(), integer()])),
  threshold: number(),
});

export const MultiSig = object({
  sigs: array(CompressedSignature),
  bitmap: array(integer()),
  multisig_pk: MultiSigPublicKey,
});

export type MultiSigPublicKey = Infer<typeof MultiSigPublicKey>;
export type MultiSig = Infer<typeof MultiSig>;

export function toMultiSigAddress(
  pks: PubkeyWeightPair[],
  threshold: Uint8Array,
  ): string {
    let maxLength = 1 + 64 * 10 + 1 * 10 + 2;
    let tmp = new Uint8Array(maxLength);
    tmp.set([SIGNATURE_SCHEME_TO_FLAG['MultiSig']]);
    tmp.set(threshold, 1);
    let i = 3;
    for (const pk of pks) {
      tmp.set(pk.pubKey.flag(), i);
      tmp.set(pk.pubKey.toBytes(), i + 1);
      tmp.set([pk.weight], i + 1 + pk.pubKey.toBytes().length);
      i += pk.pubKey.toBytes().length + 2;
    }
    return normalizeSuiAddress(
      bytesToHex(blake2b(tmp.slice(0, i), { dkLen: 32 })).slice(0, SUI_ADDRESS_LENGTH * 2),
    );
}

export function combinePartialSigs(
  pairs: SerializedSignature[],
  pks: PubkeyWeightPair[],
  threshold: Uint8Array
): SerializedSignature {
  let multisig_pk: MultiSigPublicKey = {
    pk_map: pks.map((pk) => [pk.pubKey.toBase64(), pk.weight]),
    threshold: threshold[0],
  };
  // 10 sig + 10 pk + 10 flag + u16 as 2
  let maxLength = 64 * 10 + 10 * 33 + 10 + 2;
  const serializedSignature = new Uint8Array(maxLength);
  serializedSignature.set([SIGNATURE_SCHEME_TO_FLAG['MultiSig']]);
  const bitmap3 = new RoaringBitmap32();
  let compressed_sigs: CompressedSignature[] = new Array(pairs.length);

  for (let i = 0; i < pairs.length; i++) { 
    let parsed = fromSerializedSignature(pairs[i]);
    compressed_sigs[i] = {
        flag: SIGNATURE_SCHEME_TO_FLAG[parsed.signatureScheme],
        sig: Array.from(parsed.signature, (byte) => byte)
      };
    for (let j = 0; j < pks.length; j++) {
      if (parsed.pubKey.equals(pks[j].pubKey)) {
        bitmap3.add(j);
        break;
      }
    }
  }
  let multisig: MultiSig = {
    sigs: compressed_sigs,
    bitmap: bitmap3.toArray(),
    multisig_pk: multisig_pk,
  }; 
  const bytes = builder.ser('MultiSig', multisig).toBytes();
  let tmp = new Uint8Array(bytes.length + 1);
  tmp.set([SIGNATURE_SCHEME_TO_FLAG['MultiSig']]);
  tmp.set(bytes, 1);
  return toB64(tmp);
}

export function decodeMultiSig(signature: string): SignaturePubkeyPair[] {
    const parsed = fromB64(signature);
    if (parsed.length < 1 || parsed[0] !== SIGNATURE_SCHEME_TO_FLAG['MultiSig']) {
      throw new Error('Invalid MultiSig flag');
    };

    const multisig: MultiSig = builder.de('MultiSig', parsed.slice(1));
    let res: SignaturePubkeyPair[] = new Array(10);
    for (let i = 0; i < multisig.sigs.length; i++) {
      let s: CompressedSignature = multisig.sigs[i];
      let pk_index = multisig.bitmap.at(i);
      let scheme = SIGNATURE_FLAG_TO_SCHEME[s.flag as SignatureFlag];
      let pk_str = multisig.multisig_pk.pk_map[pk_index as number][0];
      if (scheme === 'ED25519') {
        res[i] = {
          signatureScheme: scheme,
          signature: Uint8Array.from(s.sig),
          pubKey: new Ed25519PublicKey(pk_str),
        };
      } else if (scheme === 'Secp256k1') {
        res[i] = {
          signatureScheme: scheme,
          signature: Uint8Array.from(s.sig),
          pubKey: new Secp256k1PublicKey(pk_str),
        };
      } else {
        throw new Error('Invalid Signature Scheme');
      }
    }
    return res;
  }