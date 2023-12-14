'use client';
import { useSearchParams } from 'next/navigation';
import { ReactElement, useState } from 'react';
import { set } from 'zod';

export default function Page() {
  const searchParams = useSearchParams();
  const [isHuman, setIsHuman] = useState(false);

  const proof = searchParams.get('proof');
  let proofDisplay = (
    <div>
      No proof has been provided. Please go to{' '}
      <a href="https://localhost:3000/#/dashboard" className="text-blue-500">
        {' '}
        Gitcoin Passport{' '}
      </a>{' '}
      in order to generate a proof
    </div>
  );

  if (proof !== null) {
    proofDisplay = <div>{proof}</div>;
  }

  const verifyProof = async () => {
    setIsHuman(true);
  }

  const doVote = async () => {
  }

  const voting = isHuman ? (<div>
    Congratulations, you have proven to be a human!
    Please send your vote!
    <br />
    <button onClick={doVote}>Vote</button>
  </div>) : null;


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
              href="https://localhost:3000/#/dashboard"
              className="text-blue-500"
            >
              <em>Redirect me to the Passport App</em>
            </a>
          </p>

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
