'use client';
import { useSearchParams } from 'next/navigation';
import { ReactElement, use, useEffect, useState } from 'react';
import { number, set } from 'zod';
import {
  BarretenbergBackend,
  CompiledCircuit,
} from '@noir-lang/backend_barretenberg';
import { Noir, ProofData, WitnessMap } from '@noir-lang/noir_js';
import zk_passport_score from '../../target/zk_passport_score.json';
import axios from 'axios';

export default function Page() {
  const searchParams = useSearchParams();
  const [isHuman, setIsHuman] = useState(false);
  const [jsonProof, setJsonProof] = useState('');
  const [hashes, setHashes] = useState<string[]>([]);
  const [duplicateStampUsage, setDuplicateStampUsage] = useState<string>('');
  const [registerVoteStatus, setRegisterVoteStatus] = useState<string>('');
  let proofDisplay = (
    <div>
      No proof has been provided. Please go to{' '}
      <a href="http://localhost:3000/#/" className="text-blue-500">
        {' '}
        Gitcoin Passport{' '}
      </a>{' '}
      in order to generate a proof
    </div>
  );

  if (jsonProof !== '') {
    proofDisplay = <div>{jsonProof}</div>;
  }
  function uint8ArrayToHexString(uint8Array: Uint8Array) {
    return uint8Array.reduce(
      (str, byte) => str + byte.toString(16).padStart(2, '0'),
      '',
    );
  }

  useEffect(() => {
    try {
      const publicInputs = new Uint8Array(64);
      JSON.parse(jsonProof)['publicInputs'].forEach((x: any, idx:number) => {
        const value = BigInt(x[1]);
        console.log("geri:", x[0], value, Number(value));
        publicInputs[idx] = Number(value);
      });

      console.log("Hash 1:", publicInputs.slice(0, 32));
      console.log("Hash 2:", publicInputs.slice(32));
      const hashes = [
        '0x' + uint8ArrayToHexString(publicInputs.slice(0, 32)),
        '0x' + uint8ArrayToHexString(publicInputs.slice(32)),
      ];
      setHashes(hashes);
      console.log('geri hashes:', hashes);
    } catch (error) {
      console.log(error);
    }
  }, [jsonProof]);

  const verifyProof = async () => {
    const backend = new BarretenbergBackend(
      zk_passport_score as CompiledCircuit,
    );
    const noir = new Noir(zk_passport_score as CompiledCircuit, backend);
    const jsonProofObj = JSON.parse(jsonProof);

    const proof: ProofData = {
      proof: new Uint8Array(jsonProofObj.proof),
      publicInputs: new Map<number, string>(jsonProofObj.publicInputs),
    };
    console.log('geri proof', proof);
    const verification = await noir.verifyFinalProof(proof);
    console.log(verification);
    setIsHuman(true);
  };

  const doVote = async () => {};

  const checkDuplicateStamps = async () => {
    const requestResponse = await axios.post(
      'http://127.0.0.1:8002/account/votes_are_clear',
      {
        hashes: hashes,
      },
    );
    console.log('requestResponse', requestResponse);
    console.log('requestResponse', requestResponse.data);
    if (requestResponse.status === 200 && requestResponse.data.ok) {
      setDuplicateStampUsage('All hashes look good!');
    } else {
      setDuplicateStampUsage('Your are trying to cheat!');
    }
  };

  const registerVote = async () => {
    try {
      const requestResponse = await axios.post(
        'http://127.0.0.1:8002/account/register_vote',
        {
          hashes: hashes,
        },
      );
      console.log('requestResponse', requestResponse);
      if (requestResponse.status === 200 && requestResponse.data.ok) {
        setRegisterVoteStatus('Your vote has been registered!');
      } else {
        setRegisterVoteStatus(
          'Unable to register your vote ... Are you trying to cheat?',
        );
      }
    } catch (error) {
      console.error(error);
      setRegisterVoteStatus(
        'ERROR: Unable to register your vote ... Are you trying to cheat?',
      );
    }
  };

  const voting = isHuman ? (
    <div>
      Congratulations, you have proven to be a human! Please continue ...
      <br />
      <br />
      <button onClick={checkDuplicateStamps}>
        Check duplicate stamp usage
      </button>
      <br />
      <br />
      {duplicateStampUsage}
      <br />
      <br />
      <button onClick={registerVote}>Register my vote</button>
      <br />
      <br />
      {registerVoteStatus}
      <br />
      <br />
    </div>
  ) : null;

  return (
    <main className="flex min-h-screen flex-col p-6">
      <div className="flex h-20 shrink-0 items-end rounded-lg bg-blue-500 p-4 md:h-52">
        <h1>Voting for Humans</h1>
      </div>
      <div className="mt-4 flex grow flex-col gap-4 md:flex-row">
        <div className="flex flex-col justify-center gap-6 rounded-lg bg-gray-50 px-6 py-10 md:w-2/5 md:px-20">
          <p className={`text-xl text-gray-800 md:text-3xl md:leading-normal`}>
            <strong>Welcome to Voting for Humans.</strong>
            <br />
            In order to vote you must provide a ZK Proof for your humanity.
            Please go to the Passport App, and generate your ZK Proof.
            <br />
            <br />
            <a
              href="http://localhost:3000/#/"
              className="text-blue-500"
            >
              <em>Redirect me to the Passport App</em>
            </a>
          </p>

          <textarea
            defaultValue={jsonProof}
            onChange={(e) => setJsonProof(e.target.value)}
            rows={40}
            cols={120}
          />
          <pre>{jsonProof}</pre>
          <h3>Your Proof</h3>
          <pre>{proofDisplay}</pre>

          <button onClick={verifyProof}>Verify Proof</button>
          <br />
          <br />
          {voting}
        </div>

        <div className="flex items-center justify-center p-6 md:w-3/5 md:px-28 md:py-12">
          {/* Add Hero Images Here */}
        </div>
      </div>
    </main>
  );
}
