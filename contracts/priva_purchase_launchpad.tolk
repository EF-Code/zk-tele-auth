import "@stdlib/tvm-dicts"
import "priva_purchase_auth_verifier"

contract PrivaPurchaseLaunchpad {
    description: "Immutable native-TON Priva purchase composition"
    incomingMessages: PrivaPurchaseLaunchpadPurchase
}

/// A deliberately narrow native-TON launchpad composition.  The accepted
/// asset is TON, the purchase recipient is the message sender, and the price
/// and caps are immutable StateInit policy.  Entitlements are accounted for in
/// this contract; a separate audited token settlement adapter is required
/// before representing them as jettons or NFTs.
struct PrivaPurchaseLaunchpadAccounting {
    pricePerUnit: coins
    perIdentityCap: uint64
    inventory: uint64
    sold: uint64
    totalRaised: coins
    usedActionNullifiers: map<uint256, uint64>
    usedQueryIds: map<uint64, bool>
    identityTotals: map<uint256, uint64>
    refundCredits: map<uint256, coins>
}

struct PrivaPurchaseLaunchpadStorage {
    appDomainHash: uint256
    issuerKeyHash: uint256
    launchIdHash: uint256
    maxTokenAgeSec: uint32
    requirePremium: uint8
    maxAuthorizationTtlSec: uint32
    accounting: Cell<PrivaPurchaseLaunchpadAccounting>
}

struct PrivaPurchaseLaunchpadPurchase {
    queryId: uint64
    quantity: uint64
    recipient: address
    proof: cell
    pubInputs: cell
}

struct (0x50555243) PrivaPurchaseLaunchpadWithdrawRefund {
    queryId: uint64
}

enum PrivaPurchaseLaunchpadErrors {
    InvalidInputs = 258,
    NotConfigured = 267,
    WrongDomain = 268,
    WrongIssuer = 269,
    WrongLaunch = 270,
    WrongLaunchpad = 271,
    WrongRecipient = 272,
    WrongOperation = 273,
    WrongVersion = 274,
    StaleAuthorization = 275,
    Replay = 276,
    IdentityCap = 277,
    Inventory = 278,
    Payment = 279,
    Arithmetic = 280,
    RefundUnavailable = 281,
    UnsupportedMessage = 282,
}

const PRIVA_PURCHASE_LAUNCHPAD_BUY: int = 1
const PRIVA_PURCHASE_LAUNCHPAD_VERSION: int = 1
const PRIVA_PURCHASE_LAUNCHPAD_MIN_PROCESSING_VALUE: coins = 50000000
const PRIVA_PURCHASE_LAUNCHPAD_STORAGE_RESERVE: coins = 100000000
// Bounds dictionary growth so storage fees remain measurable and fundable.
const PRIVA_PURCHASE_LAUNCHPAD_MAX_INVENTORY: uint64 = 1000000
const PRIVA_PURCHASE_LAUNCHPAD_MAX_UINT32: int = 4294967295

/// Kept local so the source compiles against both the pinned tolk-js runtime
/// and older Acton toolchains that do not ship gas-payments.tolk.
const PRIVA_PURCHASE_LAUNCHPAD_RESERVE_MODE_AT_MOST: int = 2
fun reserveLaunchpadStorage(nanoGrams: coins, reserveMode: int): void
    asm "RAWRESERVE"

fun PrivaPurchaseLaunchpadStorage.load(): PrivaPurchaseLaunchpadStorage {
    val data = contract.getData();
    val dp = data.beginParse();
    if (dp.remainingBitsCount() == 0 && dp.remainingRefsCount() == 0) {
        return PrivaPurchaseLaunchpadStorage {
            appDomainHash: 0,
            issuerKeyHash: 0,
            launchIdHash: 0,
            maxTokenAgeSec: 0,
            requirePremium: 0,
            maxAuthorizationTtlSec: 0,
            accounting: PrivaPurchaseLaunchpadAccounting {
                pricePerUnit: 0,
                perIdentityCap: 0,
                inventory: 0,
                sold: 0,
                totalRaised: 0,
                usedActionNullifiers: [],
                usedQueryIds: [],
                identityTotals: [],
                refundCredits: [],
            }.toCell(),
        };
    }
    val result = PrivaPurchaseLaunchpadStorage.fromCell(data);
    return result;
}

fun PrivaPurchaseLaunchpadStorage.save(self) {
    contract.setData(self.toCell());
}

fun loadPublicSignals(verifier: PrivaPurchaseAuthVerifier, pubInputs: cell): array<int> {
    return verifier.parsePubInputs(pubInputs);
}

fun addressLimbs(addr: address): (uint256, uint256) {
    val (workchain, accountId) = addr.getWorkchainAndHash();
    if (workchain != 0) { throw PrivaPurchaseLaunchpadErrors.WrongRecipient; }
    val high = accountId / 340282366920938463463374607431768211456;
    val low = accountId % 340282366920938463463374607431768211456;
    return (high, low);
}

fun PrivaPurchaseLaunchpadStorage.checkPolicy(self, sender: address, attachedValue: coins, msg: PrivaPurchaseLaunchpadPurchase, pub: array<int>) {
    val accounting = self.accounting.load();
    if (
        self.appDomainHash == 0 || self.issuerKeyHash == 0 || self.launchIdHash == 0 ||
        self.maxTokenAgeSec == 0 || self.maxAuthorizationTtlSec == 0 ||
        accounting.pricePerUnit == 0 || accounting.perIdentityCap == 0 || accounting.inventory == 0 ||
        accounting.perIdentityCap > PRIVA_PURCHASE_LAUNCHPAD_MAX_INVENTORY || accounting.inventory > PRIVA_PURCHASE_LAUNCHPAD_MAX_INVENTORY ||
        (self.requirePremium != 0 && self.requirePremium != 1)
    ) {
        throw PrivaPurchaseLaunchpadErrors.NotConfigured;
    }
    if (pub.size() != 17 || pub.get(2) != 1) { throw PrivaPurchaseLaunchpadErrors.InvalidInputs; }
    if (
        pub.get(4) < 0 || pub.get(4) > PRIVA_PURCHASE_LAUNCHPAD_MAX_UINT32 ||
        pub.get(5) < 1 || pub.get(5) > PRIVA_PURCHASE_LAUNCHPAD_MAX_UINT32 ||
        pub.get(15) < 0 || pub.get(15) > PRIVA_PURCHASE_LAUNCHPAD_MAX_UINT32
    ) { throw PrivaPurchaseLaunchpadErrors.InvalidInputs; }
    if (pub.get(3) != self.appDomainHash) { throw PrivaPurchaseLaunchpadErrors.WrongDomain; }
    if (pub.get(7) != self.issuerKeyHash) { throw PrivaPurchaseLaunchpadErrors.WrongIssuer; }
    if (pub.get(8) != self.launchIdHash) { throw PrivaPurchaseLaunchpadErrors.WrongLaunch; }
    if (pub.get(5) != self.maxTokenAgeSec) { throw PrivaPurchaseLaunchpadErrors.WrongVersion; }
    val (launchpadWorkchain, launchpadHash) = contract.getAddress().getWorkchainAndHash();
    if (launchpadWorkchain != 0) { throw PrivaPurchaseLaunchpadErrors.WrongLaunchpad; }
    val expectedHi = launchpadHash / 340282366920938463463374607431768211456;
    val expectedLo = launchpadHash % 340282366920938463463374607431768211456;
    if (pub.get(9) != expectedHi || pub.get(10) != expectedLo) { throw PrivaPurchaseLaunchpadErrors.WrongLaunchpad; }
    if (pub.get(11) != PRIVA_PURCHASE_LAUNCHPAD_BUY) { throw PrivaPurchaseLaunchpadErrors.WrongOperation; }
    if (pub.get(16) != PRIVA_PURCHASE_LAUNCHPAD_VERSION) { throw PrivaPurchaseLaunchpadErrors.WrongVersion; }
    if (pub.get(4) > blockchain.now() + 300 || blockchain.now() > pub.get(4) + self.maxTokenAgeSec) {
        throw PrivaPurchaseLaunchpadErrors.StaleAuthorization;
    }
    if (pub.get(15) < pub.get(4) || blockchain.now() > pub.get(15) || pub.get(15) - pub.get(4) > self.maxAuthorizationTtlSec) {
        throw PrivaPurchaseLaunchpadErrors.StaleAuthorization;
    }
    if (pub.get(6) != self.requirePremium) { throw PrivaPurchaseLaunchpadErrors.WrongVersion; }
    val (recipientWorkchain, recipientHash) = msg.recipient.getWorkchainAndHash();
    if (recipientWorkchain != 0 || msg.recipient != sender) { throw PrivaPurchaseLaunchpadErrors.WrongRecipient; }
    val recipientHi = recipientHash / 340282366920938463463374607431768211456;
    val recipientLo = recipientHash % 340282366920938463463374607431768211456;
    if (pub.get(12) != recipientHi || pub.get(13) != recipientLo) { throw PrivaPurchaseLaunchpadErrors.WrongRecipient; }
    if (msg.quantity == 0 || msg.quantity > accounting.inventory) { throw PrivaPurchaseLaunchpadErrors.Inventory; }
    if (accounting.pricePerUnit > 0 && msg.quantity > 18446744073709551615 / accounting.pricePerUnit) { throw PrivaPurchaseLaunchpadErrors.Arithmetic; }
    val expectedPayment = accounting.pricePerUnit * msg.quantity;
    if (attachedValue < expectedPayment + PRIVA_PURCHASE_LAUNCHPAD_MIN_PROCESSING_VALUE) { throw PrivaPurchaseLaunchpadErrors.Payment; }
}

fun onInternalMessage(inMsg: InMessage) {
    // An empty internal message only activates a precomputed StateInit.  It
    // cannot configure or mutate launch policy.
    if (inMsg.body.isEmpty()) { return; }
    val purchase = lazy PrivaPurchaseLaunchpadPurchase.fromSlice(inMsg.body);
    match (purchase) {
        PrivaPurchaseLaunchpadPurchase => {
            val messageTail = purchase.forceLoadLazyObject();
            if (!messageTail.isEmpty()) { throw PrivaPurchaseLaunchpadErrors.InvalidInputs; }
            val verifier = PrivaPurchaseAuthVerifier.create();
            val proofMsg = PrivaPurchaseAuthVerifierVerify { proof: purchase.proof, pubInputs: purchase.pubInputs };
            val storage = PrivaPurchaseLaunchpadStorage.load();
            val publicSignals = loadPublicSignals(verifier, purchase.pubInputs);
            storage.checkPolicy(inMsg.senderAddress, inMsg.valueCoins, purchase, publicSignals);
            if (!verifier.verifyProof(proofMsg)) { throw PrivaPurchaseLaunchpadErrors.InvalidInputs; }

            var next = storage;
            var accounting = next.accounting.load();
            val action = publicSignals.get(1) as uint256;
            // Action nullifiers prevent proof replay; query IDs additionally
            // make duplicate message delivery idempotent when a caller
            // supplies a fresh authorization for an already-used query.
            if (accounting.usedActionNullifiers.exists(action) || accounting.usedQueryIds.exists(purchase.queryId)) {
                throw PrivaPurchaseLaunchpadErrors.Replay;
            }
            accounting.usedActionNullifiers.set(action, purchase.quantity);
            accounting.usedQueryIds.set(purchase.queryId, true);
            val identity = publicSignals.get(0) as uint256;
            val previous = accounting.identityTotals.get(identity);
            val alreadyBought: uint64 = previous.isFound ? previous.loadValue() : 0;
            if (alreadyBought > accounting.perIdentityCap || purchase.quantity > accounting.perIdentityCap - alreadyBought) { throw PrivaPurchaseLaunchpadErrors.IdentityCap; }
            accounting.identityTotals.set(identity, alreadyBought + purchase.quantity);
            accounting.inventory -= purchase.quantity;
            accounting.sold += purchase.quantity;
            accounting.totalRaised += accounting.pricePerUnit * purchase.quantity;
            next.accounting = accounting.toCell();
            next.save();

            // Overpayment is credited to the canonical sender hash. The
            // purchase path intentionally emits no asynchronous settlement
            // action, so a bounce or downstream failure cannot strand value or
            // roll back only part of the accounting. A separately audited
            // withdrawal adapter can redeem this credit.
            val expectedPayment = accounting.pricePerUnit * purchase.quantity;
            val refund = inMsg.valueCoins - expectedPayment - PRIVA_PURCHASE_LAUNCHPAD_MIN_PROCESSING_VALUE;
            reserveLaunchpadStorage(PRIVA_PURCHASE_LAUNCHPAD_STORAGE_RESERVE, PRIVA_PURCHASE_LAUNCHPAD_RESERVE_MODE_AT_MOST);
            if (refund > 0) {
                val (_, recipientHash) = purchase.recipient.getWorkchainAndHash();
                val previousRefund = accounting.refundCredits.get(recipientHash);
                val currentRefund: coins = previousRefund.isFound ? previousRefund.loadValue() : 0;
                accounting.refundCredits.set(recipientHash, currentRefund + refund);
                next.accounting = accounting.toCell();
                next.save();
            }
        }
        else => throw PrivaPurchaseLaunchpadErrors.UnsupportedMessage,
    }
}

/// The getters expose only deployment/operations state; none is used as an
/// authorization input.  `identityTotal` is intentionally read-only.
get fun launchPolicy(): (int, int, int, int, int, int, int, int, int, int) {
    val s = PrivaPurchaseLaunchpadStorage.load();
    val a = s.accounting.load();
    return (s.appDomainHash, s.issuerKeyHash, s.launchIdHash, s.maxTokenAgeSec, s.requirePremium, s.maxAuthorizationTtlSec, a.pricePerUnit, a.perIdentityCap, a.inventory, a.sold);
}

get fun totalRaised(): int { return PrivaPurchaseLaunchpadStorage.load().accounting.load().totalRaised; }
get fun usedAction(actionNullifier: int): int {
    val r = PrivaPurchaseLaunchpadStorage.load().accounting.load().usedActionNullifiers.get(actionNullifier as uint256);
    return r.isFound ? r.loadValue() : 0;
}
get fun usedQuery(queryId: int): int {
    return PrivaPurchaseLaunchpadStorage.load().accounting.load().usedQueryIds.exists(queryId as uint64) ? 1 : 0;
}
get fun identityPurchased(identityNullifier: int): int {
    val r = PrivaPurchaseLaunchpadStorage.load().accounting.load().identityTotals.get(identityNullifier as uint256);
    return r.isFound ? r.loadValue() : 0;
}
get fun refundCredit(recipientHash: int): int {
    val r = PrivaPurchaseLaunchpadStorage.load().accounting.load().refundCredits.get(recipientHash as uint256);
    return r.isFound ? r.loadValue() : 0;
}
