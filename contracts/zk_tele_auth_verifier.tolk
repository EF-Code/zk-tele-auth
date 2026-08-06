
import "@stdlib/exotic-cells"
import "@stdlib/tvm-dicts"

contract ZkTeleAuthVerifier {
  description: "Groth16 verifier + application layer (domain binding, freshness, nullifier replay protection)"
  storage: ZkTeleAuthVerifierStorage
  incomingMessages: ZkTeleAuthAllowedMessage
}

/// Application layer built on top of the stateless Groth16 core:
///  - binds every accepted proof to the configured app-domain commitment
///  - enforces initData freshness (currentTimestamp + maxTokenAgeSec >= now)
///  - rejects nullifier replays: each anonymous user id verifies exactly once
///
/// The contract is deployed unconfigured; the first `ZkTeleAuthConfigure`
/// message (sent by the deployer) pins the app domain and freshness window.
/// After configuration the domain commitment is immutable.

/// Persistent contract storage.
struct ZkTeleAuthVerifierStorage {
  appDomainHash: uint256
  maxTokenAgeSec: uint32
  verifiedCount: uint64
  usedNullifiers: dict
}

fun ZkTeleAuthVerifierStorage.load(): ZkTeleAuthVerifierStorage {
  val data = contract.getData();
  val dp = data.beginParse();
  if (dp.remainingBitsCount() == 0 && dp.remainingRefsCount() == 0) {
    return ZkTeleAuthVerifierStorage {
      appDomainHash: 0,
      maxTokenAgeSec: 0,
      verifiedCount: 0,
      usedNullifiers: createEmptyDict(),
    };
  }
  return ZkTeleAuthVerifierStorage.fromCell(data);
}

fun ZkTeleAuthVerifierStorage.save(self) {
  contract.setData(self.toCell());
}

/// Configure the verifier (deploy-time only). Opcode "ZKCF".
struct (0x5a4b4346) ZkTeleAuthConfigure {
  appDomainHash: uint256
  maxTokenAgeSec: uint32
}

type ZkTeleAuthAllowedMessage = ZkTeleAuthVerifierVerify | ZkTeleAuthConfigure

struct ZkTeleAuthVerifier {
  ic0: slice
  ic1: slice
  ic2: slice
  ic3: slice
  ic4: slice
  ic5: slice
  ic6: slice
  vkGamma2: slice
  vkDelta2: slice
  vkAlpha1: slice
  vkBeta2: slice
  nPublic: int
}

const ZkTeleAuthVerifierMinVerifyValue: coins = 50000000

enum ZkTeleAuthVerifierErrors {
  InvalidInputs = 258,
  WrongProof = 260,
  NotEnoughValue = 261,
  NotVerified = 262,
  WrongDomain = 263,
  StaleProof = 264,
  Replay = 265,
  NotConfigured = 266,
  AlreadyConfigured = 267,
}

fun ZkTeleAuthVerifier.create(): ZkTeleAuthVerifier {
  return ZkTeleAuthVerifier {
    ic0: "a810cc730dc915a107afe36e7795a3876c244b16e45101c896a23f0c45cbc30f3e4ab7dcab472a6a0d688f121ded2823".hexToSlice(),
    ic1: "af4ba9dde37245088f9ce73387a5c84968540c29d4c24e3b9a306d9d633394a0d8bc5875ace8a86616d20e33977d6828".hexToSlice(),
    ic2: "b08ddee6391012294c7c4a09f821e93718dc7749220beaeacf34e9c2d28ce631796cb4f962f1826f09809ed66374b041".hexToSlice(),
    ic3: "903fe810d3ac22d6c029e353129c39920db68f5a86743db4b207565e5fc1da1d3db58070a743cda0787517dc184057d8".hexToSlice(),
    ic4: "82c2e0c80d11a2719463f23a169f7826ee59ac564d61e0919878878ee506ae36d414396c0a2cd37d3591bf08748dd145".hexToSlice(),
    ic5: "879602bf8d0c1ed1b0a74944a28a3b8e1b069dc99259f3380d6a1b5d7e43427d95ff14b97c68680e35a2be112e07a11a".hexToSlice(),
    ic6: "ac1c8191eb93fe838350c941aa523f83b4b1978ed86ed829b94bb62dca317a6851e8582ec271e060962f94c174cb94b8".hexToSlice(),
    vkGamma2: "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8".hexToSlice(),
    vkDelta2: "981496858f94a1315209fa60581822bbb25e9adef52455a02d638bd0e620ccea91fe8412b8ac377dc743d2c584c0e5a01878e79c3d2ff513cda7418001b1f88a3bf26227c8c3cabdfcfe806ba4cfebda2794debdf97b110b61095997b59a80b6".hexToSlice(),
    vkAlpha1: "b1a165b133f010873b4e28e2bffbe464f35ab3bba2096a64185a38eedbae3bcb964f1e5fde242c52207bbc74eb608a47".hexToSlice(),
    vkBeta2: "944180c45e7f9324264158ad9385c3e94a5424ce318430fbd4bdf8541354013b77590fa5e743d779698dc544f9e7b3b41073988e48a694033b6bdff5d9aa0f62e7d57a066237d3b9f2c868bcfc7348d757815bd0e501bd276a33c73c56fd2ec8".hexToSlice(),
    nPublic: 6,
  };
}

/// # Safety
/// Expects both slices to contain canonically encoded BLS12-381 G1 points
/// accepted by the TVM `BLS_G1_ADD` opcode.
@pure fun ZkTeleAuthVerifier.blsG1Add(x: slice, y: slice): slice asm "BLS_G1_ADD";

/// # Safety
/// Expects the slice to contain a canonically encoded BLS12-381 G1 point
/// accepted by the TVM `BLS_G1_NEG` opcode.
@pure fun ZkTeleAuthVerifier.blsG1Neg(x: slice): slice asm "BLS_G1_NEG";

@pure fun ZkTeleAuthVerifier.blsG1InGroup(x: slice): bool asm "BLS_G1_INGROUP";
@pure fun ZkTeleAuthVerifier.blsG2InGroup(x: slice): bool asm "BLS_G2_INGROUP";
@pure fun ZkTeleAuthVerifier.blsG1IsZero(x: slice): bool asm "BLS_G1_ISZERO";
@pure fun ZkTeleAuthVerifier.blsG2IsZero(x: slice): bool asm "BLS_G2_ISZERO";

fun ZkTeleAuthVerifier.checkProofPoints(piA: slice, piB: slice, piC: slice) {
  if (
    piA.remainingBitsCount() != 384 || piA.remainingRefsCount() != 0 ||
    piB.remainingBitsCount() != 768 || piB.remainingRefsCount() != 0 ||
    piC.remainingBitsCount() != 384 || piC.remainingRefsCount() != 0
  ) {
    throw ZkTeleAuthVerifierErrors.InvalidInputs;
  }
  if (!ZkTeleAuthVerifier.blsG1InGroup(piA) || !ZkTeleAuthVerifier.blsG2InGroup(piB) || !ZkTeleAuthVerifier.blsG1InGroup(piC)) {
    throw ZkTeleAuthVerifierErrors.InvalidInputs;
  }
  if (ZkTeleAuthVerifier.blsG1IsZero(piA) || ZkTeleAuthVerifier.blsG2IsZero(piB) || ZkTeleAuthVerifier.blsG1IsZero(piC)) {
    throw ZkTeleAuthVerifierErrors.InvalidInputs;
  }
}

fun ZkTeleAuthVerifier.loadCheckedG1(point: cell): slice {
  val (pointSlice, isExotic) = point.beginParseSpecial();
  if (isExotic || pointSlice.remainingBitsCount() != 384 || pointSlice.remainingRefsCount() != 0) {
    throw ZkTeleAuthVerifierErrors.InvalidInputs;
  }
  return pointSlice;
}

fun ZkTeleAuthVerifier.loadCheckedG2(point: cell): slice {
  val (pointSlice, isExotic) = point.beginParseSpecial();
  if (isExotic || pointSlice.remainingBitsCount() != 768 || pointSlice.remainingRefsCount() != 0) {
    throw ZkTeleAuthVerifierErrors.InvalidInputs;
  }
  return pointSlice;
}

fun ZkTeleAuthVerifier.loadCheckedProof(proof: cell): (slice, slice, slice) {
  val (initialProof, isExotic) = proof.beginParseSpecial();
  var proofSlice = initialProof;
  if (isExotic || proofSlice.remainingBitsCount() != 0 || proofSlice.remainingRefsCount() != 3) {
    throw ZkTeleAuthVerifierErrors.InvalidInputs;
  }
  val piA = ZkTeleAuthVerifier.loadCheckedG1(proofSlice.loadRef());
  val piB = ZkTeleAuthVerifier.loadCheckedG2(proofSlice.loadRef());
  val piC = ZkTeleAuthVerifier.loadCheckedG1(proofSlice.loadRef());
  proofSlice.assertEnd();
  return (piA, piB, piC);
}

@pure fun ZkTeleAuthVerifier.blsR(): int asm "BLS_PUSHR";

fun ZkTeleAuthVerifier.checkPublicInput(x: int): int {
  // TVM scalar multiplication reduces modulo r, so x and x+r would otherwise alias.
  if (x < 0 || x >= ZkTeleAuthVerifier.blsR()) {
    throw ZkTeleAuthVerifierErrors.InvalidInputs;
  }
  return x;
}

/// # Safety
/// Expects the provided slices to contain canonically encoded BLS12-381 proof
/// and verification-key points in the order required by TVM `BLS_PAIRING`.
@pure fun ZkTeleAuthVerifier.blsPairing(
  x1: slice, y1: slice,
  x2: slice, y2: slice,
  x3: slice, y3: slice,
  x4: slice, y4: slice,
  n: int
): int asm "BLS_PAIRING";

/// # Safety
/// Expects x1..x6 to be canonical BLS12-381 G1 points and y1..y6
/// to be scalars encoded in the format expected by TVM `BLS_G1_MULTIEXP`.
@pure
fun ZkTeleAuthVerifier.blsG1Multiexp6(
  x1: slice, y1: int,
  x2: slice, y2: int,
  x3: slice, y3: int,
  x4: slice, y4: int,
  x5: slice, y5: int,
  x6: slice, y6: int,
  n: int
): slice asm "BLS_G1_MULTIEXP";


// Internal messages carry public inputs as a custom payload:
// uint8 length, then canonical three-int257 chunks chained through refs.
fun ZkTeleAuthVerifier.checkPublicInputsPayloadShape(payload: slice) {
  var remaining: int = 6;

  while (remaining > 0) {
    var chunk: int = remaining;
    if (chunk > 3) { chunk = 3; }
    if (payload.remainingBitsCount() != chunk * 257) { throw ZkTeleAuthVerifierErrors.InvalidInputs; }
    remaining -= chunk;

    if (remaining > 0) {
      if (payload.remainingRefsCount() != 1) { throw ZkTeleAuthVerifierErrors.InvalidInputs; }
      val (nextPayload, isExotic) = payload.loadRef().beginParseSpecial();
      if (isExotic) { throw ZkTeleAuthVerifierErrors.InvalidInputs; }
      payload = nextPayload;
    } else if (payload.remainingRefsCount() != 0) {
      throw ZkTeleAuthVerifierErrors.InvalidInputs;
    }
  }
}

fun ZkTeleAuthVerifier.loadNextPubInput(mutate payload: slice): int {
  if (payload.remainingBitsCount() < 257) {
    if (payload.remainingBitsCount() != 0 || payload.remainingRefsCount() != 1) {
      throw ZkTeleAuthVerifierErrors.InvalidInputs;
    }
    val (nextPayload, isExotic) = payload.loadRef().beginParseSpecial();
    if (isExotic || nextPayload.remainingBitsCount() < 257) {
      throw ZkTeleAuthVerifierErrors.InvalidInputs;
    }
    payload = nextPayload;
  }
  return ZkTeleAuthVerifier.checkPublicInput(payload.loadInt(257));
}

fun ZkTeleAuthVerifier.finishGroth16(
  self,
  piA: slice,
  piB: slice,
  piC: slice,
  acc: slice,
  haveAcc: bool
): bool {
  // Final cpub = IC0 + acc (IC0 is always added exactly once)
  var cpub: slice;
  if (!haveAcc) {
    cpub = self.ic0;
  } else {
    cpub = ZkTeleAuthVerifier.blsG1Add(acc, self.ic0);
  }

  // Pairing check: e(cpub, gamma) * e(-piA, piB) * e(piC, delta) * e(alpha, beta) == 1
  val piANeg: slice = ZkTeleAuthVerifier.blsG1Neg(piA);
  val ok: int = ZkTeleAuthVerifier.blsPairing(
    cpub,         self.vkGamma2,
    piANeg,       piB,
    piC,          self.vkDelta2,
    self.vkAlpha1, self.vkBeta2,
    4
  );

  return ok != 0;
}

fun ZkTeleAuthVerifier.verifyPayload(
  self,
  piA: slice,
  piB: slice,
  piC: slice,
  mutate payload: slice
): bool {
  ZkTeleAuthVerifier.checkProofPoints(piA, piB, piC);

  // Compute: cpub = IC0 + sum(pubInputs[i] * IC(i+1))
  var haveAcc: bool = false;
  var acc: slice = self.ic0; // placeholder until haveAcc == true

  val y1: int = ZkTeleAuthVerifier.loadNextPubInput(mutate payload);
  val y2: int = ZkTeleAuthVerifier.loadNextPubInput(mutate payload);
  val y3: int = ZkTeleAuthVerifier.loadNextPubInput(mutate payload);
  val y4: int = ZkTeleAuthVerifier.loadNextPubInput(mutate payload);
  val y5: int = ZkTeleAuthVerifier.loadNextPubInput(mutate payload);
  val y6: int = ZkTeleAuthVerifier.loadNextPubInput(mutate payload);
  acc = ZkTeleAuthVerifier.blsG1Multiexp6(
    self.ic1, y1,
    self.ic2, y2,
    self.ic3, y3,
    self.ic4, y4,
    self.ic5, y5,
    self.ic6, y6
    , 6
  );
  haveAcc = true;

  if (payload.remainingBitsCount() != 0 || payload.remainingRefsCount() != 0) {
    throw ZkTeleAuthVerifierErrors.InvalidInputs;
  }

  return self.finishGroth16(piA, piB, piC, acc, haveAcc);
}

fun ZkTeleAuthVerifier.verify(self, piA: slice, piB: slice, piC: slice, pubInputs: array<int>): bool {
  ZkTeleAuthVerifier.checkProofPoints(piA, piB, piC);
  if (pubInputs.size() != self.nPublic) { throw ZkTeleAuthVerifierErrors.InvalidInputs; }

  // Compute: cpub = IC0 + sum(pubInputs[i] * IC(i+1))
  var haveAcc: bool = false;
  var acc: slice = self.ic0; // placeholder until haveAcc == true

  acc = ZkTeleAuthVerifier.blsG1Multiexp6(
    self.ic1, ZkTeleAuthVerifier.checkPublicInput(pubInputs.get(0)),
    self.ic2, ZkTeleAuthVerifier.checkPublicInput(pubInputs.get(1)),
    self.ic3, ZkTeleAuthVerifier.checkPublicInput(pubInputs.get(2)),
    self.ic4, ZkTeleAuthVerifier.checkPublicInput(pubInputs.get(3)),
    self.ic5, ZkTeleAuthVerifier.checkPublicInput(pubInputs.get(4)),
    self.ic6, ZkTeleAuthVerifier.checkPublicInput(pubInputs.get(5))
    , 6
  );
  haveAcc = true;

  return self.finishGroth16(piA, piB, piC, acc, haveAcc);
}

/// Internal message containing Groth16 proof points and serialized public inputs.
struct (0x3b3cca17) ZkTeleAuthVerifierVerify {
  /// Ordinary cell with exactly three refs: piA, piB, piC.
  proof: cell
  /// Ordinary cell with uint8 length followed by a linear int257 ref chain.
  pubInputs: cell
}

fun ZkTeleAuthVerifier.verifyProof(self, msg: ZkTeleAuthVerifierVerify): bool {
  val (piA, piB, piC) = ZkTeleAuthVerifier.loadCheckedProof(msg.proof);
  val (initialPayload, payloadIsExotic) = msg.pubInputs.beginParseSpecial();
  var payload = initialPayload;

  if (payloadIsExotic || payload.remainingBitsCount() < 8) { throw ZkTeleAuthVerifierErrors.InvalidInputs; }
  if (payload.loadUint(8) != self.nPublic) { throw ZkTeleAuthVerifierErrors.InvalidInputs; }
  ZkTeleAuthVerifier.checkPublicInputsPayloadShape(payload);

  return self.verifyPayload(piA, piB, piC, mutate payload);
}

// Convenience standalone entrypoints. Remove or rename them when composing
// multiple verifier structs inside one contract.
/// Parse the serialized public signals (uint8 count + linear int257 ref chain)
/// into an array. Layout (outputs first, matching snarkjs/circom order):
///   [0] nullifierHash, [1] isVerified, [2] appDomainHash,
///   [3] currentTimestamp, [4] maxTokenAgeSec, [5] isPremiumRequired
fun ZkTeleAuthVerifier.parsePubInputs(self, pubInputsCell: cell): array<int> {
  val (initialPayload, payloadIsExotic) = pubInputsCell.beginParseSpecial();
  if (payloadIsExotic || initialPayload.remainingBitsCount() < 8) { throw ZkTeleAuthVerifierErrors.InvalidInputs; }
  var payload = initialPayload;
  if (payload.loadUint(8) != self.nPublic) { throw ZkTeleAuthVerifierErrors.InvalidInputs; }
  ZkTeleAuthVerifier.checkPublicInputsPayloadShape(payload);

  var out: array<int> = [];
  repeat (self.nPublic) {
    out.push(ZkTeleAuthVerifier.loadNextPubInput(mutate payload));
  }
  if (payload.remainingBitsCount() != 0 || payload.remainingRefsCount() != 0) {
    throw ZkTeleAuthVerifierErrors.InvalidInputs;
  }
  return out;
}

/// Application-layer checks applied AFTER the Groth16 pairing equation:
/// the proof must be valid, the public gate must be satisfied, the app-domain
/// commitment must match this contract's configuration, and the initData
/// timestamp must be fresh (not stale, not forged in the future).
fun ZkTeleAuthVerifier.checkAppSignals(self, storage: ZkTeleAuthVerifierStorage, pubInputs: array<int>) {
  assert (storage.appDomainHash != 0) throw ZkTeleAuthVerifierErrors.NotConfigured;
  assert (pubInputs.get(1) == 1) throw ZkTeleAuthVerifierErrors.NotVerified;
  assert (pubInputs.get(2) == storage.appDomainHash) throw ZkTeleAuthVerifierErrors.WrongDomain;

  val proofTime = pubInputs.get(3);
  val proofAge = pubInputs.get(4);
  val nowTs = blockchain.now();
  val skew = 300;
  assert (proofTime <= nowTs + skew) throw ZkTeleAuthVerifierErrors.StaleProof;
  assert (nowTs <= proofTime + proofAge) throw ZkTeleAuthVerifierErrors.StaleProof;
}

fun onInternalMessage(inMsg: InMessage) {
  val msg = lazy ZkTeleAuthAllowedMessage.fromSlice(inMsg.body);

  match (msg) {
    ZkTeleAuthConfigure => {
      var storage = ZkTeleAuthVerifierStorage.load();
      assert (storage.appDomainHash == 0) throw ZkTeleAuthVerifierErrors.AlreadyConfigured;
      storage.appDomainHash = msg.appDomainHash;
      storage.maxTokenAgeSec = msg.maxTokenAgeSec;
      storage.save();
    }
    ZkTeleAuthVerifierVerify => {
      assert (inMsg.valueCoins >= ZkTeleAuthVerifierMinVerifyValue) throw ZkTeleAuthVerifierErrors.NotEnoughValue;
      val messageTail = msg.forceLoadLazyObject();
      if (!messageTail.isEmpty()) { throw ZkTeleAuthVerifierErrors.InvalidInputs; }

      // 1. Real Groth16 pairing check over BLS12-381.
      assert (ZkTeleAuthVerifier.create().verifyProof(msg)) throw ZkTeleAuthVerifierErrors.WrongProof;

      // 2. Application-layer checks on the public signals.
      var storage = ZkTeleAuthVerifierStorage.load();
      val pubInputs = ZkTeleAuthVerifier.create().parsePubInputs(msg.pubInputs);
      ZkTeleAuthVerifier.create().checkAppSignals(storage, pubInputs);

      // 3. Nullifier replay protection: store each anonymous id once.
      var used = storage.usedNullifiers;
      val inserted = used.uDictSetIfNotExists(256, pubInputs.get(0), createEmptySlice());
      assert (inserted) throw ZkTeleAuthVerifierErrors.Replay;
      storage.usedNullifiers = used;

      // 4. Persist counters.
      storage.verifiedCount += 1;
      storage.save();
    }
    else => {
      assert (inMsg.body.isEmpty()) throw ZkTeleAuthVerifierErrors.InvalidInputs;
    }
  }
}

/// Number of proofs accepted since deployment.
get fun verifiedCount(): int {
  return ZkTeleAuthVerifierStorage.load().verifiedCount;
}

/// Whether the app domain commitment has been pinned by a configure message.
get fun isConfigured(): bool {
  return ZkTeleAuthVerifierStorage.load().appDomainHash != 0;
}

/// Bound app-domain commitment (0 until configured).
get fun appDomainHash(): int {
  return ZkTeleAuthVerifierStorage.load().appDomainHash;
}

/// Verifies a Groth16 proof against public inputs.
get fun verify_ZkTeleAuthVerifier(piA: slice, piB: slice, piC: slice, pubInputs: array<int>): bool {
  return ZkTeleAuthVerifier.create().verify(piA, piB, piC, pubInputs);
}
