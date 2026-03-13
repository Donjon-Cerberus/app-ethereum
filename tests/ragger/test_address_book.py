import hashlib
import hmac as hmac_module
import struct
from typing import Optional

from bip_utils import Bip39SeedGenerator, Bip32Slip10Nist256p1
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.bip import pack_derivation_path
from ragger.bip.seed import SPECULOS_MNEMONIC

from client.client import EthAppClient
from client.status_word import StatusWord
from client.address_book import AddressBookClient, AddressBookSubCommand, AddressBookResponseType


# =============================================================================
# Constants (must match SDK address_book_crypto.c)
# =============================================================================

HMAC_KDF_SALT_IDENTITY       = b"AddressBook-Identity"
HMAC_KDF_SALT_LEDGER_ACCOUNT = b"AddressBook-LedgerAccount"
HMAC_PROOF_LENGTH            = 32
CONTACT_ID_LENGTH            = 16
BLOCKCHAIN_FAMILY_ETHEREUM   = 1

# Fixed test contact IDs — simulating wallet-generated random values
TEST_CONTACT_ID_ALICE = bytes(range(CONTACT_ID_LENGTH))          # 0x00..0x0f
TEST_CONTACT_ID_BOB   = bytes(range(1, CONTACT_ID_LENGTH + 1))   # 0x01..0x10

# Fixed Path
TEST_BIP32_PATH = "m/44'/60'/0'/0/0"


# =============================================================================
# Crypto helpers
# =============================================================================

def bip32_path_to_list(path: str) -> list[int]:
    """Parse a BIP32 path string into a list of raw indices."""
    raw = pack_derivation_path(path)
    n = raw[0]
    return [struct.unpack('>I', raw[1 + i*4: 5 + i*4])[0] for i in range(n)]


def _derive_privkey(bip32_path: str) -> bytes:
    """Derive secp256r1 private key (SLIP-10) at the given BIP32 path."""
    seed_bytes = Bip39SeedGenerator(SPECULOS_MNEMONIC).Generate()
    ctx = Bip32Slip10Nist256p1.FromSeed(seed_bytes)
    for level in bip32_path_to_list(bip32_path):
        ctx = ctx.ChildKey(level)
    return ctx.PrivateKey().Raw().ToBytes()


def derive_hmac_key_identity(bip32_path: str) -> bytes:
    """KDF for Identity HMAC: SHA256("AddressBook-Identity" || privkey.d)"""
    privkey_d = _derive_privkey(bip32_path)
    h = hashlib.sha256()
    h.update(HMAC_KDF_SALT_IDENTITY)
    h.update(privkey_d)
    return h.digest()


def derive_hmac_key_ledger_account(bip32_path: str) -> bytes:
    """KDF for Ledger Account HMAC: SHA256("AddressBook-LedgerAccount" || privkey.d)"""
    privkey_d = _derive_privkey(bip32_path)
    h = hashlib.sha256()
    h.update(HMAC_KDF_SALT_LEDGER_ACCOUNT)
    h.update(privkey_d)
    return h.digest()


def compute_hmac_name(bip32_path: str,
                      contact_id: bytes,
                      contact_name: str) -> bytes:
    """Compute HMAC_NAME for an Identity contact.

    Mirrors address_book_compute_hmac_name() in C.
    Message: contact_id(16) | name_len(1) | name
    """
    assert len(contact_id) == CONTACT_ID_LENGTH
    key        = derive_hmac_key_identity(bip32_path)
    name_bytes = contact_name.encode('utf-8')
    msg = contact_id + bytes([len(name_bytes)]) + name_bytes
    return hmac_module.new(key, msg, hashlib.sha256).digest()


def compute_hmac_rest(bip32_path: str,
                      contact_id: bytes,
                      contact_scope: str,
                      identifier: bytes,
                      family: int,
                      chain_id: int) -> bytes:
    """Compute HMAC_REST for an Identity contact.

    Mirrors address_book_compute_hmac_rest() in C.
    Message: contact_id(16) | scope_len(1) | scope | id_len(1) | identifier |
             family(1) [| chain_id_be(8) for FAMILY_ETHEREUM]
    """
    assert len(contact_id) == CONTACT_ID_LENGTH
    key         = derive_hmac_key_identity(bip32_path)
    scope_bytes = contact_scope.encode('utf-8')
    msg = (contact_id +
           bytes([len(scope_bytes)]) + scope_bytes +
           bytes([len(identifier)])  + identifier  +
           bytes([family]))
    if family == BLOCKCHAIN_FAMILY_ETHEREUM:
        msg += chain_id.to_bytes(8, 'big')
    return hmac_module.new(key, msg, hashlib.sha256).digest()


def compute_hmac_proof_ledger_account(bip32_path: str,
                                      contact_name: str,
                                      family: int,
                                      chain_id: int) -> bytes:
    """Compute HMAC Proof of Registration for a Ledger Account.

    Mirrors address_book_compute_hmac_proof_ledger_account() in C.
    Message: name_len(1) | name | family(1) | chain_id_be(8)
    chain_id is always encoded as 8 bytes big-endian
    """
    key        = derive_hmac_key_ledger_account(bip32_path)
    name_bytes = contact_name.encode('utf-8')
    chain_id_be = chain_id.to_bytes(8, 'big')
    msg = bytes([len(name_bytes)]) + name_bytes + bytes([family]) + chain_id_be
    return hmac_module.new(key, msg, hashlib.sha256).digest()


# =============================================================================
# Response checkers
# =============================================================================

def _check_response_generic(app_client: EthAppClient,
                            expected_type: AddressBookResponseType,
                            bip32_path: str,
                            # Identity-specific params
                            contact_id: Optional[bytes] = None,
                            contact_name: Optional[str] = None,
                            contact_scope: Optional[str] = None,
                            identifier: Optional[bytes] = None,
                            family: Optional[int] = None,
                            chain_id: Optional[int] = None) -> tuple[Optional[bytes], Optional[bytes]]:
    """Generic response verifier for all Address Book response types.

    Returns:
        (hmac_name, hmac_rest) or (hmac_proof, None) depending on response type

    Response formats by type:
        - REGISTER_IDENTITY:        1 + 32 + 32 = 65B (hmac_name + hmac_rest)
        - EDIT_CONTACT_NAME:        1 + 32      = 33B (hmac_name only)
        - EDIT_SCOPE_NAME:          1 + 32      = 33B (hmac_rest only)
        - EDIT_IDENTITY:            1 + 32      = 33B (hmac_rest only)
        - REGISTER_LEDGER_ACCOUNT:  1 + 32      = 33B (hmac_proof)
        - RENAME_LEDGER_ACCOUNT:    1 + 32      = 33B (hmac_proof)
    """
    response = app_client.response()
    assert response and response.status == StatusWord.OK, \
        f"Unexpected status: {response.status}"
    data = response.data

    # Determine expected format based on response type
    returns_name = expected_type in (
        AddressBookResponseType.TYPE_REGISTER_IDENTITY,
        AddressBookResponseType.TYPE_EDIT_CONTACT_NAME,
    )
    returns_rest = expected_type in (
        AddressBookResponseType.TYPE_REGISTER_IDENTITY,
        AddressBookResponseType.TYPE_EDIT_SCOPE_NAME,
        AddressBookResponseType.TYPE_EDIT_IDENTITY,
    )
    returns_ledger_proof = expected_type in (
        AddressBookResponseType.TYPE_REGISTER_LEDGER_ACCOUNT,
        AddressBookResponseType.TYPE_RENAME_LEDGER_ACCOUNT,
    )

    # Calculate expected length
    expected_len = 1  # type byte
    if returns_name:
        expected_len += HMAC_PROOF_LENGTH
    if returns_rest:
        expected_len += HMAC_PROOF_LENGTH
    if returns_ledger_proof:
        expected_len += HMAC_PROOF_LENGTH

    assert len(data) == expected_len, \
        f"Expected {expected_len} bytes for {expected_type.name}, got {len(data)}"

    # Verify type byte
    actual_type = data[0]
    assert actual_type == expected_type, \
        f"Unexpected response type: 0x{actual_type:02x}, expected {expected_type.name}"

    # Parse and verify HMACs
    offset = 1
    hmac_name = None
    hmac_rest = None
    hmac_proof = None

    if returns_name:
        device_hmac_name = data[offset:offset + HMAC_PROOF_LENGTH]
        offset += HMAC_PROOF_LENGTH
        assert contact_id is not None and contact_name is not None, \
            "contact_id and contact_name required for HMAC_NAME"
        expected_hmac_name = compute_hmac_name(bip32_path, contact_id, contact_name)
        assert device_hmac_name == expected_hmac_name, (
            f"HMAC_NAME mismatch:\n"
            f"  device:   {device_hmac_name.hex()}\n"
            f"  expected: {expected_hmac_name.hex()}"
        )
        hmac_name = device_hmac_name

    if returns_rest:
        device_hmac_rest = data[offset:offset + HMAC_PROOF_LENGTH]
        offset += HMAC_PROOF_LENGTH
        assert all(p is not None for p in [contact_id, contact_scope, identifier, family, chain_id]), \
            "All Identity params required for HMAC_REST"
        expected_hmac_rest = compute_hmac_rest(bip32_path, contact_id, contact_scope,
                                               identifier, family, chain_id)
        assert device_hmac_rest == expected_hmac_rest, (
            f"HMAC_REST mismatch:\n"
            f"  device:   {device_hmac_rest.hex()}\n"
            f"  expected: {expected_hmac_rest.hex()}"
        )
        hmac_rest = device_hmac_rest

    if returns_ledger_proof:
        device_hmac_proof = data[offset:offset + HMAC_PROOF_LENGTH]
        offset += HMAC_PROOF_LENGTH
        assert all(p is not None for p in [contact_name, family, chain_id]), \
            "contact_name, family, and chain_id required for Ledger Account HMAC"
        expected_hmac_proof = compute_hmac_proof_ledger_account(bip32_path, contact_name,
                                                                family, chain_id)
        assert device_hmac_proof == expected_hmac_proof, (
            f"HMAC_PROOF mismatch:\n"
            f"  device:   {device_hmac_proof.hex()}\n"
            f"  expected: {expected_hmac_proof.hex()}"
        )
        hmac_proof = device_hmac_proof

    # Return appropriate tuple based on what was verified
    if returns_ledger_proof:
        return (hmac_proof, None)
    return (hmac_name, hmac_rest)


def check_identity_response(app_client: EthAppClient,
                            bip32_path: str,
                            contact_id: bytes,
                            contact_name: str,
                            contact_scope: str,
                            identifier: bytes,
                            family: int,
                            chain_id: int) -> tuple[bytes, bytes]:
    """Verify the Register Identity response and return (hmac_name, hmac_rest)."""
    hmac_name, hmac_rest = _check_response_generic(
        app_client,
        AddressBookResponseType.TYPE_REGISTER_IDENTITY,
        bip32_path,
        contact_id=contact_id,
        contact_name=contact_name,
        contact_scope=contact_scope,
        identifier=identifier,
        family=family,
        chain_id=chain_id,
    )
    print("✓ Register Identity: HMAC_NAME and HMAC_REST verified")
    return hmac_name, hmac_rest


def check_ledger_account_response(app_client: EthAppClient,
                                  bip32_path: str,
                                  contact_name: str,
                                  family: int,
                                  chain_id: int) -> bytes:
    """Verify the Register Ledger Account response and return the HMAC proof."""
    hmac_proof, _ = _check_response_generic(
        app_client,
        AddressBookResponseType.TYPE_REGISTER_LEDGER_ACCOUNT,
        bip32_path,
        contact_name=contact_name,
        family=family,
        chain_id=chain_id,
    )
    print("✓ HMAC Proof of Registration (Ledger Account) verified")
    return hmac_proof


def check_edit_contact_name_response(app_client: EthAppClient,
                                     bip32_path: str,
                                     contact_id: bytes,
                                     new_contact_name: str) -> bytes:
    """Verify the Edit Contact Name response and return the new HMAC_NAME."""
    hmac_name, _ = _check_response_generic(
        app_client,
        AddressBookResponseType.TYPE_EDIT_CONTACT_NAME,
        bip32_path,
        contact_id=contact_id,
        contact_name=new_contact_name,
    )
    print("✓ Edit Contact Name: HMAC_NAME verified")
    return hmac_name


def check_edit_identity_response(app_client: EthAppClient,
                                 bip32_path: str,
                                 contact_id: bytes,
                                 contact_scope: str,
                                 new_identifier: bytes,
                                 family: int,
                                 chain_id: int) -> bytes:
    """Verify the Edit Identity response and return the new HMAC_REST."""
    _, hmac_rest = _check_response_generic(
        app_client,
        AddressBookResponseType.TYPE_EDIT_IDENTITY,
        bip32_path,
        contact_id=contact_id,
        contact_scope=contact_scope,
        identifier=new_identifier,
        family=family,
        chain_id=chain_id,
    )
    print("✓ Edit Identity: HMAC_REST verified")
    return hmac_rest


def check_edit_scope_name_response(app_client: EthAppClient,
                                   bip32_path: str,
                                   contact_id: bytes,
                                   new_contact_scope: str,
                                   identifier: bytes,
                                   family: int,
                                   chain_id: int) -> bytes:
    """Verify the Edit Scope Name response and return the new HMAC_REST."""
    _, hmac_rest = _check_response_generic(
        app_client,
        AddressBookResponseType.TYPE_EDIT_SCOPE_NAME,
        bip32_path,
        contact_id=contact_id,
        contact_scope=new_contact_scope,
        identifier=identifier,
        family=family,
        chain_id=chain_id,
    )
    print("✓ Edit Scope Name: HMAC_REST verified")
    return hmac_rest


def check_rename_ledger_account_response(app_client: EthAppClient,
                                         bip32_path: str,
                                         new_account_name: str,
                                         family: int,
                                         chain_id: int) -> bytes:
    """Verify the Rename Ledger Account response and return the new HMAC proof."""
    hmac_proof, _ = _check_response_generic(
        app_client,
        AddressBookResponseType.TYPE_RENAME_LEDGER_ACCOUNT,
        bip32_path,
        contact_name=new_account_name,
        family=family,
        chain_id=chain_id,
    )
    print("✓ HMAC Proof of Registration (Rename Ledger Account) verified")
    return hmac_proof


# =============================================================================
# Test helpers
# =============================================================================

def _common_register_identity(scenario_navigator: NavigateWithScenario,
                              app_client: EthAppClient,
                              addr_book: AddressBookClient,
                              contact_name: str = "Alice",
                              contact_scope: str = "Eth Address 1",
                              identifier: bytes = bytes.fromhex("6b175474e89094c44da98b954eedeac495271d0f"),
                              do_compare: bool = True) -> tuple[bytes, bytes]:
    """Common helper to register an Identity contact.

    Args:
        scenario_navigator: Test navigator
        app_client: Ethereum app client
        addr_book: Address book client
        contact_name: Contact name
        contact_scope: Optional contact scope (address name)
        identifier: Address bytes (20 bytes for Ethereum)
        do_compare: If False, uses "/register" test suffix to skip snapshot comparison

    Returns:
        Tuple of (hmac_name, hmac_rest)
    """
    # Fixed values for all Identity registrations
    contact_id = TEST_CONTACT_ID_ALICE
    path = TEST_BIP32_PATH
    chain_id = 1

    apdu = addr_book.prepare_register_identity(
        contact_name,
        contact_id,
        identifier,
        path,
        chain_id,
        contact_scope=contact_scope,
    )

    # Determine test_name based on do_compare
    test_name = None if do_compare else f"{scenario_navigator.test_name}/register"

    with app_client.provide_address_book(addr_book,
                                         apdu,
                                         AddressBookSubCommand.SUB_CMD_REGISTER_IDENTITY):
        scenario_navigator.address_review_approve(
            test_name=test_name,
            custom_screen_text="Approve",
        )

    return check_identity_response(
        app_client, path, contact_id, contact_name, contact_scope, identifier,
        BLOCKCHAIN_FAMILY_ETHEREUM, chain_id)


def _common_register_ledger_account(scenario_navigator: NavigateWithScenario,
                                    app_client: EthAppClient,
                                    addr_book: AddressBookClient,
                                    contact_name: str,
                                    do_compare: bool = True) -> bytes:
    """Common helper to register a Ledger Account.

    Args:
        scenario_navigator: Test navigator
        app_client: Ethereum app client
        addr_book: Address book client
        contact_name: Account name
        do_compare: If False, uses "/register" test suffix to skip snapshot comparison

    Returns:
        HMAC proof
    """
    # Fixed values for all Ledger Account registrations
    path = TEST_BIP32_PATH
    chain_id = 1

    apdu = addr_book.prepare_register_ledger_account(contact_name, path, chain_id)

    # Determine test_name based on do_compare
    test_name = None if do_compare else f"{scenario_navigator.test_name}/register"

    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_REGISTER_LEDGER_ACCOUNT):
        scenario_navigator.address_review_approve(
            test_name=test_name,
            custom_screen_text="Approve",
        )

    return check_ledger_account_response(
        app_client, path, contact_name, BLOCKCHAIN_FAMILY_ETHEREUM, chain_id)


# =============================================================================
# Tests — Register Identity
# =============================================================================

def test_address_book_register_identity(scenario_navigator: NavigateWithScenario) -> None:
    """Test Register Identity: bind a name + scope to an Ethereum address.

    Verifies that the device returns two valid HMACs (HMAC_NAME and HMAC_REST)
    that can be independently re-derived from the same inputs.
    """
    backend  = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    _common_register_identity(scenario_navigator, app_client, addr_book)


# =============================================================================
# Tests — Edit Identifier
# =============================================================================

def test_address_book_edit_identifier(scenario_navigator: NavigateWithScenario) -> None:
    """Test Edit Identifier: change the identifier of an existing contact.

    Flow:
      1. Register Identity for "Alice" with address_old → receive (hmac_name, hmac_rest_old)
      2. Edit Identity: address_old → address_new, providing hmac_rest_old
      3. Verify the returned new HMAC_REST covers (contact_id, scope, address_new)
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    contact_name = "Alice"
    address_old = bytes.fromhex("6b175474e89094c44da98b954eedeac495271d0f")
    address_new = bytes.fromhex("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")

    # Step 1: Register Identity (skip snapshot comparison)
    hmac_name_old, hmac_rest_old = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        contact_name,
        identifier=address_old,
        do_compare=False,
    )

    # Step 2: Edit Identity (address_old → address_new)
    apdu = addr_book.prepare_edit_identity(
        contact_name, TEST_CONTACT_ID_ALICE, address_new, address_old, TEST_BIP32_PATH, 1,
        hmac_name_old, hmac_rest_old,
        contact_scope="Eth Address 1",
    )
    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_EDIT_IDENTITY):
        scenario_navigator.address_review_approve(
            test_name=f"{scenario_navigator.test_name}/edit",
            custom_screen_text="Approve",
        )
    check_edit_identity_response(app_client, TEST_BIP32_PATH, TEST_CONTACT_ID_ALICE, "Eth Address 1", address_new,
                                 BLOCKCHAIN_FAMILY_ETHEREUM, 1)


# =============================================================================
# Tests — Edit Contact Name
# =============================================================================

def test_address_book_edit_contact_name(scenario_navigator: NavigateWithScenario) -> None:
    """Test Edit Contact Name: rename an existing contact.

    Flow:
      1. Register Identity for "Alice" → receive (hmac_name_old, hmac_rest)
      2. Edit Contact Name "Alice" → "Bob", providing only contact_id + hmac_name_old
         (no identifier, scope, or network needed)
      3. Verify the returned HMAC_NAME covers (contact_id, "Bob")
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    old_name = "Alice"
    new_name = "Bob"

    # Step 1: Register Identity (skip snapshot comparison)
    hmac_name_old, _ = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        contact_name=old_name,
        do_compare=False,
    )

    # Step 2: Edit Contact Name (Alice → Bob) — only needs contact_id + names + path + HMAC_NAME
    apdu = addr_book.prepare_edit_contact_name(
        old_name, new_name, TEST_CONTACT_ID_ALICE, TEST_BIP32_PATH, hmac_name_old,
    )
    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_EDIT_CONTACT_NAME):
        scenario_navigator.address_review_approve(
            test_name=f"{scenario_navigator.test_name}/edit",
            custom_screen_text="Approve",
        )
    check_edit_contact_name_response(app_client, TEST_BIP32_PATH, TEST_CONTACT_ID_ALICE, new_name)


# =============================================================================
# Tests — Edit Scope Name
# =============================================================================

def test_address_book_edit_scope_name(scenario_navigator: NavigateWithScenario) -> None:
    """Test Edit Scope Name: change the scope of an existing contact.

    Flow:
      1. Register Identity for "Alice" with scope "Eth Address 1"
         → receive (hmac_name, hmac_rest_old)
      2. Edit Scope Name "Eth Address 1" → "Eth Savings", providing hmac_rest_old
      3. Verify the returned HMAC_REST covers (contact_id, "Eth Savings", identifier, ...)
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    contact_name = "Alice"
    old_scope = "Eth Address 1"
    new_scope = "Eth Savings"

    # Step 1: Register Identity (skip snapshot comparison)
    hmac_name_old, hmac_rest_old = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        contact_name,
        contact_scope=old_scope,
        do_compare=False,
    )

    # Step 2: Edit Scope Name
    apdu = addr_book.prepare_edit_scope_name(
        contact_name, TEST_CONTACT_ID_ALICE, old_scope, new_scope,
        bytes.fromhex("6b175474e89094c44da98b954eedeac495271d0f"),
        TEST_BIP32_PATH, 1,
        hmac_name_old, hmac_rest_old,
    )
    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_EDIT_SCOPE_NAME):
        scenario_navigator.address_review_approve(
            test_name=f"{scenario_navigator.test_name}/edit",
            custom_screen_text="Approve",
        )
    check_edit_scope_name_response(app_client, TEST_BIP32_PATH, TEST_CONTACT_ID_ALICE, new_scope,
                                   bytes.fromhex("6b175474e89094c44da98b954eedeac495271d0f"),
                                   BLOCKCHAIN_FAMILY_ETHEREUM, 1)


# =============================================================================
# Tests — Register Ledger Account
# =============================================================================

def test_address_book_register_ledger_account(scenario_navigator: NavigateWithScenario) -> None:
    """Test Register Ledger Account: bind a name to a BIP32 derivation path."""
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    _common_register_ledger_account(
        scenario_navigator, app_client, addr_book,
        contact_name="ETH main address",
    )


# =============================================================================
# Tests — Rename Ledger Account
# =============================================================================

def test_address_book_rename_ledger_account(scenario_navigator: NavigateWithScenario) -> None:
    """Test Rename Ledger Account: rename an existing account.

    Flow:
      1. Register Ledger Account "ETH main address" → receive hmac_proof_old
      2. Rename → "ETH savings", providing hmac_proof_old
      3. Verify the new HMAC proof matches the proof for "ETH savings"
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    old_name = "ETH main address"
    new_name = "ETH savings"

    # Step 1: Register Ledger Account (skip snapshot comparison)
    hmac_proof_old = _common_register_ledger_account(
        scenario_navigator, app_client, addr_book,
        contact_name=old_name,
        do_compare=False,
    )

    # Step 2: Rename Ledger Account
    apdu = addr_book.prepare_rename_ledger_account(old_name, new_name, TEST_BIP32_PATH, 1, hmac_proof_old)
    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_RENAME_LEDGER_ACCOUNT):
        scenario_navigator.address_review_approve(
            test_name=f"{scenario_navigator.test_name}/rename",
            custom_screen_text="Approve",
        )
    check_rename_ledger_account_response(app_client, TEST_BIP32_PATH, new_name, BLOCKCHAIN_FAMILY_ETHEREUM, 1)
