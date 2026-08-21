
import "@stdlib/exotic-cells"
import "@stdlib/tvm-dicts"

contract ZkTeleAuthVerifier {
  description: "Issuer-bound Telegram Groth16 verifier with immutable StateInit policy"
  storage: ZkTeleAuthVerifierStorage
  incomingMessages: ZkTeleAuthVerifierVerify
}

/// Policy is serialized into StateInit data. Because contract addresses commit
/// to StateInit, there is no first-caller configuration path to front-run.
struct ZkTeleAuthVerifierStorage {
  appDomainHash: uint256
  issuerKeyHash: uint256
  maxTokenAgeSec: uint32
  requirePremium: uint8
  verifiedCount: uint64
  usedNullifiers: dict
}

fun ZkTeleAuthVerifierStorage.load(): ZkTeleAuthVerifierStorage {
  val data = contract.getData();
  val dp = data.beginParse();
  if (dp.remainingBitsCount() == 0 && dp.remainingRefsCount() == 0) {
    return ZkTeleAuthVerifierStorage {
      appDomainHash: 0,
      issuerKeyHash: 0,
      maxTokenAgeSec: 0,
      requirePremium: 0,
      verifiedCount: 0,
      usedNullifiers: createEmptyDict(),
    };
  }
  return ZkTeleAuthVerifierStorage.fromCell(data);
}

fun ZkTeleAuthVerifierStorage.save(self) {
  contract.setData(self.toCell());
}

struct ZkTeleAuthVerifier {
  ic0: slice
  ic1: slice
  ic2: slice
  ic3: slice
  ic4: slice
  ic5: slice
  ic6: slice
  ic7: slice
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
  WrongIssuer = 267,
  WrongPolicy = 268,
}

fun ZkTeleAuthVerifier.create(): ZkTeleAuthVerifier {
  return ZkTeleAuthVerifier {
    ic0: "b932a458740e1518a9dc6e296640c9c59fae1a5b377ceb7a4beeae1cad9dd95f72d8946b1ee918ecc2455101bdd46888".hexToSlice(),
    ic1: "8f7c778a70693e3582b4d3199154bf028d279978610cef24cb8a6a6577b221863281f29834464c921122eca7e6e8805c".hexToSlice(),
    ic2: "96132349a9ee6af007df9e9af7b64f8d420ad1ee9e36921fb58fcac29f41ea4ce8c16d2598fa76a8f7c4c509a00daff9".hexToSlice(),
    ic3: "b8ca6410916aaa1d9a36ffa35cb4057d5a2dab70baf2b799ac0cbd96996dfac8bdc601dd81d1d3c09661abf70d198a06".hexToSlice(),
    ic4: "a4ae9a0701dc6278b6b3fc7c56617dfa467a0a0e6698e9e7f16c8cc59280c04b80f1cb1c74539c9a496ef67326288e3a".hexToSlice(),
    ic5: "b4876f5a03654c26aa8eebe66ebc2083f485421ec76bee4fe94fe583ea755d72cfc637a38ccdcfe1a06a9bda996e1394".hexToSlice(),
    ic6: "a7b36e41919f4d8b8722ef7edb0d65dec381066a6e2af29e6aaf06d7980e22f78629bb3cd98e84624e52ac0f703b0f5f".hexToSlice(),
    ic7: "8977f103e082f447ca3ac6ad7f6dd509ccb9ca47974d96d32f66435567e1b9f10ddce3b22b8808dd333a1d3e31f466aa".hexToSlice(),
    vkGamma2: "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8".hexToSlice(),
    vkDelta2: "b537974d6342acf224c3f3c7d5b2d4869407a66fea45c480e8121fa9a32e76e2da60045ac84ac509eccf74202eec2e560413d4965ee250dc81ffebf89d23a958f8885d1f17c014f5b8ca4bdc07c739e70d0377c7c710d6f710e9b495901c2e6a".hexToSlice(),
    vkAlpha1: "80b1bf6930d14b52fa03f6e4db586b8919df657b7a07f7b58931667caed3397b3466d55dde3eab193eca46e686dd6d50".hexToSlice(),
    vkBeta2: "aace77a76ed46078db19b14185743d3eb8414b8e5e0b70c9eeca91ff625a7578b7ef6cbe98320048185b56e57579821b06385bb3a753ad0b10013543c6baee66f8bb344b3b76f197cf49faa8927c8a33d73d22c665c5e8593e23cfe5f315c133".hexToSlice(),
    nPublic: 7,
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
/// Expects x1..x7 to be canonical BLS12-381 G1 points and y1..y7
/// to be scalars encoded in the format expected by TVM `BLS_G1_MULTIEXP`.
@pure
fun ZkTeleAuthVerifier.blsG1Multiexp7(
  x1: slice, y1: int,
  x2: slice, y2: int,
  x3: slice, y3: int,
  x4: slice, y4: int,
  x5: slice, y5: int,
  x6: slice, y6: int,
  x7: slice, y7: int,
  n: int
): slice asm "BLS_G1_MULTIEXP";


// Internal messages carry public inputs as a custom payload:
// uint8 length, then canonical three-int257 chunks chained through refs.
fun ZkTeleAuthVerifier.checkPublicInputsPayloadShape(payload: slice) {
  var remaining: int = 7;

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
  val y7: int = ZkTeleAuthVerifier.loadNextPubInput(mutate payload);
  acc = ZkTeleAuthVerifier.blsG1Multiexp7(
    self.ic1, y1,
    self.ic2, y2,
    self.ic3, y3,
    self.ic4, y4,
    self.ic5, y5,
    self.ic6, y6,
    self.ic7, y7
    , 7
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

  acc = ZkTeleAuthVerifier.blsG1Multiexp7(
    self.ic1, ZkTeleAuthVerifier.checkPublicInput(pubInputs.get(0)),
    self.ic2, ZkTeleAuthVerifier.checkPublicInput(pubInputs.get(1)),
    self.ic3, ZkTeleAuthVerifier.checkPublicInput(pubInputs.get(2)),
    self.ic4, ZkTeleAuthVerifier.checkPublicInput(pubInputs.get(3)),
    self.ic5, ZkTeleAuthVerifier.checkPublicInput(pubInputs.get(4)),
    self.ic6, ZkTeleAuthVerifier.checkPublicInput(pubInputs.get(5)),
    self.ic7, ZkTeleAuthVerifier.checkPublicInput(pubInputs.get(6))
    , 7
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

/// Parse the seven public signals in circom/snarkjs order:
/// [nullifierHash, isVerified, appDomainHash, currentTimestamp,
///  maxTokenAgeSec, isPremiumRequired, issuerKeyHash].
fun ZkTeleAuthVerifier.parsePubInputs(self, pubInputsCell: cell): array<int> {
  val (initialPayload, payloadIsExotic) = pubInputsCell.beginParseSpecial();
  if (payloadIsExotic || initialPayload.remainingBitsCount() < 8) {
    throw ZkTeleAuthVerifierErrors.InvalidInputs;
  }
  var payload = initialPayload;
  if (payload.loadUint(8) != self.nPublic) {
    throw ZkTeleAuthVerifierErrors.InvalidInputs;
  }
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

fun ZkTeleAuthVerifier.checkAppSignals(self, storage: ZkTeleAuthVerifierStorage, pubInputs: array<int>) {
  assert (
    storage.appDomainHash != 0 &&
    storage.issuerKeyHash != 0 &&
    storage.maxTokenAgeSec > 0 &&
    (storage.requirePremium == 0 || storage.requirePremium == 1)
  ) throw ZkTeleAuthVerifierErrors.NotConfigured;
  assert (pubInputs.get(1) == 1) throw ZkTeleAuthVerifierErrors.NotVerified;
  assert (pubInputs.get(2) == storage.appDomainHash) throw ZkTeleAuthVerifierErrors.WrongDomain;
  assert (pubInputs.get(6) == storage.issuerKeyHash) throw ZkTeleAuthVerifierErrors.WrongIssuer;
  assert (pubInputs.get(4) == storage.maxTokenAgeSec) throw ZkTeleAuthVerifierErrors.WrongPolicy;
  assert (pubInputs.get(5) == storage.requirePremium) throw ZkTeleAuthVerifierErrors.WrongPolicy;

  val proofTime = pubInputs.get(3);
  val nowTs = blockchain.now();
  val skew = 300;
  assert (proofTime <= nowTs + skew) throw ZkTeleAuthVerifierErrors.StaleProof;
  assert (nowTs <= proofTime + storage.maxTokenAgeSec) throw ZkTeleAuthVerifierErrors.StaleProof;
}

fun onInternalMessage(inMsg: InMessage) {
  val msg = lazy ZkTeleAuthVerifierVerify.fromSlice(inMsg.body);

  match (msg) {
    ZkTeleAuthVerifierVerify => {
      assert (inMsg.valueCoins >= ZkTeleAuthVerifierMinVerifyValue) throw ZkTeleAuthVerifierErrors.NotEnoughValue;
      val messageTail = msg.forceLoadLazyObject();
      if (!messageTail.isEmpty()) {
        throw ZkTeleAuthVerifierErrors.InvalidInputs;
      }

      val verifier = ZkTeleAuthVerifier.create();
      var storage = ZkTeleAuthVerifierStorage.load();
      val pubInputs = verifier.parsePubInputs(msg.pubInputs);
      verifier.checkAppSignals(storage, pubInputs);
      assert (verifier.verifyProof(msg)) throw ZkTeleAuthVerifierErrors.WrongProof;

      var used = storage.usedNullifiers;
      val inserted = used.uDictSetIfNotExists(256, pubInputs.get(0), createEmptySlice());
      assert (inserted) throw ZkTeleAuthVerifierErrors.Replay;
      storage.usedNullifiers = used;
      storage.verifiedCount += 1;
      storage.save();
    }
    else => {
      assert (inMsg.body.isEmpty()) throw ZkTeleAuthVerifierErrors.InvalidInputs;
    }
  }
}


/// Verifies a Groth16 proof against public inputs.
get fun verify_ZkTeleAuthVerifier(piA: slice, piB: slice, piC: slice, pubInputs: array<int>): bool {
  return ZkTeleAuthVerifier.create().verify(piA, piB, piC, pubInputs);
}

get fun verifiedCount(): int {
  return ZkTeleAuthVerifierStorage.load().verifiedCount;
}

get fun isConfigured(): bool {
  val storage = ZkTeleAuthVerifierStorage.load();
  return storage.appDomainHash != 0 && storage.issuerKeyHash != 0 && storage.maxTokenAgeSec > 0;
}

get fun appDomainHash(): int {
  return ZkTeleAuthVerifierStorage.load().appDomainHash;
}

get fun issuerKeyHash(): int {
  return ZkTeleAuthVerifierStorage.load().issuerKeyHash;
}
