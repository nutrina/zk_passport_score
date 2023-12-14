import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect } from "chai";
import { ethers } from "hardhat";
import valid_proof from "./zk_proof.json";
import bad_proof from "./zk_proof_bad.json";

describe("Voter", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Network to that snapshot in every test.
  async function deploy() {
    // Contracts are deployed using the first signer/account by default
    const [owner, otherAccount] = await ethers.getSigners();

    const Voter = await ethers.getContractFactory("Voter");
    const voter = await Voter.deploy();

    return { voter, owner, otherAccount };
  }

  describe("Deployment", function () {
    it("Should validate good proof", async function () {
      const { voter, owner, otherAccount } = await loadFixture(deploy);

      const witnesses = valid_proof.publicInputs.map((w) => w[1]);

      const isValid = await voter.verify(
        Uint8Array.from(valid_proof.proof),
        witnesses
      );
      expect(isValid).to.be.true;
    });

    it("Should fail validation of bad proof", async function () {
      const { voter, owner, otherAccount } = await loadFixture(deploy);

      const witnesses = bad_proof.publicInputs.map((w) => w[1]);

      await expect(voter.verify(Uint8Array.from(bad_proof.proof), witnesses)).to
        .be.reverted;
    });
  });
});
