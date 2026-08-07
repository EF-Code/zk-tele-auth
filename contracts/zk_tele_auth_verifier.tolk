
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
    ic0: "8303b394734363d7a5d5db9a06969d3cbd16d7315661e484ef82a538c9d72466e7626241aa28e05972544003500f6aa4".hexToSlice(),
    ic1: "b6f65e1b1e84b7822250edc80f5111f577487204c7f30fa775cc625b10f8eddd659259b896f31058416398d32fac2383".hexToSlice(),
    ic2: "960c9f45b2343a610dabf16cdce60a766c1899fec82fb94b3fa46af66fff84e4fad0231c1260d5e73178298f7dc94778".hexToSlice(),
    ic3: "80f7774f1ae20d59b49e1036977143d981c83f0ca5c77c8f5f02a05bf4b9f84ba7ad513cdcaf47216318d0e90e1cbb9b".hexToSlice(),
    ic4: "90cc0053696a1a3c8b7fb577618e188bebab59e1c129a3220b5da4c2250b5121bf12a09afcc94bf938da53c4d3b3b197".hexToSlice(),
    ic5: "868617f8b10f9a67786f17be4955be84349acebe0550de1d763745d5d89fae462e704da1f24d7923e6968274df7a9035".hexToSlice(),
    ic6: "95ba96e527092656c4a519794ad17f27180f8bb19e338ac16d5be20c76e3d736d9c8cb29d325295be26c09010a50783a".hexToSlice(),
    ic7: "9651131941063aa7be160cbd98065eb22a4392d38ef99e903bc0cfbe94485944e95f7f96d1146b4627925fc4eebe38f4".hexToSlice(),
    vkGamma2: "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8".hexToSlice(),
    vkDelta2: "981496858f94a1315209fa60581822bbb25e9adef52455a02d638bd0e620ccea91fe8412b8ac377dc743d2c584c0e5a01878e79c3d2ff513cda7418001b1f88a3bf26227c8c3cabdfcfe806ba4cfebda2794debdf97b110b61095997b59a80b6".hexToSlice(),
    vkAlpha1: "b1a165b133f010873b4e28e2bffbe464f35ab3bba2096a64185a38eedbae3bcb964f1e5fde242c52207bbc74eb608a47".hexToSlice(),
    vkBeta2: "944180c45e7f9324264158ad9385c3e94a5424ce318430fbd4bdf8541354013b77590fa5e743d779698dc544f9e7b3b41073988e48a694033b6bdff5d9aa0f62e7d57a066237d3b9f2c868bcfc7348d757815bd0e501bd276a33c73c56fd2ec8".hexToSlice(),
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
