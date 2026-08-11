// Standalone test/deployment wrapper for the reusable verifier core.
// Launchpads must import the core directly and call verifyProof synchronously.

import "priva_purchase_auth_verifier"

fun onInternalMessage(inMsg: InMessage) {
  val msg = lazy PrivaPurchaseAuthVerifierVerify.fromSlice(inMsg.body);

  match (msg) {
    PrivaPurchaseAuthVerifierVerify => {
      assert (inMsg.valueCoins >= PRIVA_PURCHASE_AUTH_VERIFIER_MIN_VERIFY_VALUE) throw PrivaPurchaseAuthVerifierErrors.NotEnoughValue;
      val messageTail = msg.forceLoadLazyObject();
      if (!messageTail.isEmpty()) { throw PrivaPurchaseAuthVerifierErrors.InvalidInputs; }
      assert (PrivaPurchaseAuthVerifier.create().verifyProof(msg)) throw PrivaPurchaseAuthVerifierErrors.WrongProof;
    }
    else => {
      assert (inMsg.body.isEmpty()) throw PrivaPurchaseAuthVerifierErrors.InvalidInputs;
    }
  }
}
