from enum import IntEnum
from typing import Optional

from ragger.backend import BackendInterface
from ragger.bip import pack_derivation_path

from .tlv import TlvSerializable, FieldTag


class AddressBookResponseType(IntEnum):
    TYPE_REGISTER_IDENTITY       = 0x11
    TYPE_EDIT_CONTACT_NAME       = 0x12
    TYPE_REGISTER_LEDGER_ACCOUNT = 0x13
    TYPE_RENAME_LEDGER_ACCOUNT   = 0x14
    TYPE_EDIT_IDENTITY           = 0x15
    TYPE_EDIT_SCOPE_NAME         = 0x16

class AddressBookSubCommand(IntEnum):
    SUB_CMD_REGISTER_IDENTITY       = 0x01
    SUB_CMD_EDIT_CONTACT_NAME       = 0x02
    SUB_CMD_EDIT_IDENTITY           = 0x03
    SUB_CMD_EDIT_SCOPE_NAME         = 0x04
    SUB_CMD_REGISTER_LEDGER_ACCOUNT = 0x11
    SUB_CMD_RENAME_LEDGER_ACCOUNT   = 0x12


class AddressBookClient(TlvSerializable):
    """
    Client for managing Address Book on Ledger devices.
    """
    _CLA: int = 0xB0
    _INS: int = 0x10

    def __init__(self, backend: BackendInterface) -> None:
        """Initialize the Address Book client with a backend."""
        self._backend = backend

    def send_async_raw(self, p1: AddressBookSubCommand, payload: bytes):
        """Send an address book APDU, splitting into chunks when needed.

        CMD_VERIFY_SIGNED_ADDRESS payloads exceed 255 bytes, so they are
        transported as multiple APDUs using a P2-based chunking scheme:
          - First chunk  (P2=0x00): 2-byte big-endian total length + first slice
          - Next  chunks (P2=0x80): subsequent slices
        All intermediate chunks are sent synchronously (device responds 9000).
        The last chunk is sent asynchronously to allow the UI flow to proceed.

        All other commands fit in a single short APDU (P2=0x00, no framing).
        """
        MAX_CHUNK = 255
        P2_FIRST  = 0x00
        P2_NEXT   = 0x80

        if p1 not in (AddressBookSubCommand.SUB_CMD_EDIT_IDENTITY,
                      AddressBookSubCommand.SUB_CMD_EDIT_SCOPE_NAME):
            header = bytes([self._CLA, self._INS, p1, P2_FIRST, len(payload)])
            return self._backend.exchange_async_raw(header + payload)

        # Prepend 2-byte big-endian total length (mirrors the firmware framing).
        framed = len(payload).to_bytes(2, 'big') + payload
        chunks = [framed[i:i + MAX_CHUNK] for i in range(0, len(framed), MAX_CHUNK)]

        # Send all but the last chunk synchronously.
        for i, chunk in enumerate(chunks[:-1]):
            p2     = P2_FIRST if i == 0 else P2_NEXT
            header = bytes([self._CLA, self._INS, p1, p2, len(chunk)])
            self._backend.exchange_raw(header + chunk)

        # Last chunk triggers the UI flow on the device.
        p2     = P2_FIRST if len(chunks) == 1 else P2_NEXT
        last   = chunks[-1]
        header = bytes([self._CLA, self._INS, p1, p2, len(last)])
        return self._backend.exchange_async_raw(header + last)

    def prepare_rename_ledger_account(self,
                                      previous_account_name: str,
                                      new_account_name: str,
                                      derivation_path: str,
                                      chain_id: int,
                                      hmac_proof: bytes) -> bytes:
        """
        Prepare TLV payload for renaming an existing Ledger Account.

        Args:
            previous_account_name: Current (old) name of the account
            new_account_name: New name to assign to the account
            derivation_path: BIP32 path used to derive the HMAC key on device
            chain_id: Chain ID for the network
            hmac_proof: HMAC Proof of Registration from the previous registration

        Returns:
            Complete TLV payload bytes.
        """
        assert previous_account_name and len(previous_account_name) <= 32, \
            "Previous account name required (max 32 chars)"
        assert new_account_name and len(new_account_name) <= 32, \
            "New account name required (max 32 chars)"
        assert derivation_path, "Derivation path is required"
        assert chain_id > 0, "Chain ID must be greater than 0"
        assert len(hmac_proof) == 32, "HMAC proof must be 32 bytes"

        path_bytes = pack_derivation_path(derivation_path)

        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, AddressBookResponseType.TYPE_RENAME_LEDGER_ACCOUNT)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.CONTACT_NAME, new_account_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.PREVIOUS_CONTACT_NAME, previous_account_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.DERIVATION_PATH, path_bytes)
        payload += self.serialize_field(FieldTag.CHAIN_ID, chain_id)
        payload += self.serialize_field(FieldTag.HMAC_PROOF, hmac_proof)
        payload += self.serialize_field(FieldTag.BLOCKCHAIN_FAMILY, 1)  # Ethereum
        return payload

    def prepare_register_ledger_account(self,
                                        contact_name: str,
                                        derivation_path: str,
                                        chain_id: int) -> bytes:
        """
        Prepare APDU for registering a Ledger account.

        Args:
            contact_name: Name for this contact
            derivation_path: BIP32 derivation path as string (e.g., "m/44'/60'/0'/0/0")
            chain_id: Chain ID for the network

        Returns:
            Complete APDU bytes ready to send
        """
        assert contact_name, "Contact name is required"
        assert derivation_path, "Derivation path is required"
        assert chain_id > 0, "Chain ID must be greater than 0"

        # Encode derivation path using ragger's pack_derivation_path
        path_bytes = pack_derivation_path(derivation_path)

        # Build TLV payload
        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, AddressBookResponseType.TYPE_REGISTER_LEDGER_ACCOUNT)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.CONTACT_NAME, contact_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.DERIVATION_PATH, path_bytes)
        payload += self.serialize_field(FieldTag.CHAIN_ID, chain_id)
        payload += self.serialize_field(FieldTag.BLOCKCHAIN_FAMILY, 1)  # Ethereum
        return payload

    def prepare_edit_identity(self,
                              contact_name: str,
                              contact_id: bytes,
                              new_identifier: bytes,
                              previous_identifier: bytes,
                              derivation_path: str,
                              chain_id: int,
                              hmac_name_proof: bytes,
                              hmac_rest_proof: bytes,
                              contact_scope: Optional[str] = None) -> bytes:
        """
        Prepare TLV payload for editing the identifier of an existing Identity contact.

        Args:
            contact_name: Name of the contact (unchanged, for display)
            contact_id: 16-byte wallet-generated contact ID (from registration)
            new_identifier: New identifier bytes (e.g. 20-byte Ethereum address)
            previous_identifier: Current (old) identifier bytes
            derivation_path: BIP32 path used to derive the HMAC key on device
            chain_id: Chain ID for the network
            hmac_name_proof: HMAC_PROOF from the original Register Identity response (verifies contact name)
            hmac_rest_proof: HMAC_REST from the original Register Identity response (verifies identifier)
            contact_scope: Scope/namespace for the identifier (unchanged, optional)

        Returns:
            Complete TLV payload bytes.
        """
        assert contact_name and len(contact_name) <= 32, "Contact name required (max 32 chars)"
        assert len(contact_id) == 16, "contact_id must be exactly 16 bytes"
        assert len(new_identifier) > 0, "New identifier is required"
        assert len(previous_identifier) > 0, "Previous identifier is required"
        assert derivation_path, "Derivation path is required"
        assert chain_id > 0, "Chain ID must be greater than 0"
        assert len(hmac_name_proof) == 32, "HMAC_PROOF must be 32 bytes"
        assert len(hmac_rest_proof) == 32, "HMAC_REST proof must be 32 bytes"

        path_bytes = pack_derivation_path(derivation_path)

        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, AddressBookResponseType.TYPE_EDIT_IDENTITY)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.CONTACT_NAME, contact_name.encode('utf-8'))
        if contact_scope:
            payload += self.serialize_field(FieldTag.CONTACT_SCOPE, contact_scope.encode('utf-8'))
        payload += self.serialize_field(FieldTag.IDENTIFIER, new_identifier)
        payload += self.serialize_field(FieldTag.PREVIOUS_IDENTIFIER, previous_identifier)
        payload += self.serialize_field(FieldTag.CONTACT_ID, contact_id)
        payload += self.serialize_field(FieldTag.DERIVATION_PATH, path_bytes)
        payload += self.serialize_field(FieldTag.CHAIN_ID, chain_id)
        payload += self.serialize_field(FieldTag.HMAC_PROOF, hmac_name_proof)
        payload += self.serialize_field(FieldTag.HMAC_REST, hmac_rest_proof)
        payload += self.serialize_field(FieldTag.BLOCKCHAIN_FAMILY, 1)  # Ethereum
        return payload

    def prepare_edit_contact_name(self,
                                  previous_contact_name: str,
                                  new_contact_name: str,
                                  contact_id: bytes,
                                  derivation_path: str,
                                  hmac_name_proof: bytes) -> bytes:
        """
        Prepare TLV payload for editing the name of an existing Identity contact.

        Only needs contact_id + names + path + HMAC_PROOF — no identifier, scope,
        or network required (HMAC_PROOF covers only contact_id + name).

        Args:
            previous_contact_name: Current (old) name of the contact
            new_contact_name: New name to assign to the contact
            contact_id: 16-byte wallet-generated contact ID (from registration)
            derivation_path: BIP32 path used to derive the HMAC key on device
            hmac_name_proof: HMAC_PROOF from the original Register Identity response

        Returns:
            Complete TLV payload bytes.
        """
        assert previous_contact_name and len(previous_contact_name) <= 32, \
            "Previous contact name required (max 32 chars)"
        assert new_contact_name and len(new_contact_name) <= 32, \
            "New contact name required (max 32 chars)"
        assert len(contact_id) == 16, "contact_id must be exactly 16 bytes"
        assert derivation_path, "Derivation path is required"
        assert len(hmac_name_proof) == 32, "HMAC_PROOF must be 32 bytes"

        path_bytes = pack_derivation_path(derivation_path)

        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, AddressBookResponseType.TYPE_EDIT_CONTACT_NAME)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.CONTACT_NAME, new_contact_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.PREVIOUS_CONTACT_NAME, previous_contact_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.CONTACT_ID, contact_id)
        payload += self.serialize_field(FieldTag.DERIVATION_PATH, path_bytes)
        payload += self.serialize_field(FieldTag.HMAC_PROOF, hmac_name_proof)
        return payload

    def prepare_edit_scope_name(self,
                                contact_name: str,
                                contact_id: bytes,
                                previous_contact_scope: str,
                                new_contact_scope: str,
                                identifier: bytes,
                                derivation_path: str,
                                chain_id: int,
                                hmac_name_proof: bytes,
                                hmac_rest_proof: bytes) -> bytes:
        """
        Prepare TLV payload for editing the scope of an existing Identity contact.

        Args:
            contact_name: Name of the contact (unchanged, for display)
            contact_id: 16-byte wallet-generated contact ID (from registration)
            previous_contact_scope: Current (old) scope of the contact
            new_contact_scope: New scope to assign to the contact
            identifier: Raw identifier bytes (e.g. 20-byte Ethereum address)
            derivation_path: BIP32 path used to derive the HMAC key on device
            chain_id: Chain ID for the network
            hmac_name_proof: HMAC_PROOF from the original Register Identity response (verifies contact name)
            hmac_rest_proof: HMAC_REST from the original Register Identity response (verifies scope)

        Returns:
            Complete TLV payload bytes.
        """
        assert contact_name and len(contact_name) <= 32, "Contact name required (max 32 chars)"
        assert len(contact_id) == 16, "contact_id must be exactly 16 bytes"
        assert previous_contact_scope and len(previous_contact_scope) <= 32, \
            "Previous scope required (max 32 chars)"
        assert new_contact_scope and len(new_contact_scope) <= 32, \
            "New scope required (max 32 chars)"
        assert len(identifier) > 0, "Identifier is required"
        assert derivation_path, "Derivation path is required"
        assert chain_id > 0, "Chain ID must be greater than 0"
        assert len(hmac_name_proof) == 32, "HMAC_PROOF must be 32 bytes"
        assert len(hmac_rest_proof) == 32, "HMAC_REST proof must be 32 bytes"

        path_bytes = pack_derivation_path(derivation_path)

        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, AddressBookResponseType.TYPE_EDIT_SCOPE_NAME)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.CONTACT_NAME, contact_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.CONTACT_SCOPE, new_contact_scope.encode('utf-8'))
        payload += self.serialize_field(FieldTag.IDENTIFIER, identifier)
        payload += self.serialize_field(FieldTag.PREVIOUS_CONTACT_SCOPE, previous_contact_scope.encode('utf-8'))
        payload += self.serialize_field(FieldTag.CONTACT_ID, contact_id)
        payload += self.serialize_field(FieldTag.DERIVATION_PATH, path_bytes)
        payload += self.serialize_field(FieldTag.CHAIN_ID, chain_id)
        payload += self.serialize_field(FieldTag.HMAC_PROOF, hmac_name_proof)
        payload += self.serialize_field(FieldTag.HMAC_REST, hmac_rest_proof)
        payload += self.serialize_field(FieldTag.BLOCKCHAIN_FAMILY, 1)  # Ethereum
        return payload

    def prepare_register_identity(self,
                                 contact_name: str,
                                 contact_id: bytes,
                                 identifier: bytes,
                                 derivation_path: str,
                                 chain_id: int,
                                 contact_scope: Optional[str] = None) -> bytes:
        """
        Prepare APDU for registering a Contact.

        Args:
            contact_name: Name of the contact (max 32 chars, printable ASCII)
            contact_id: 16-byte wallet-generated unique contact ID (never displayed)
            identifier: Unique identifier for the contact (e.g. 20-byte Ethereum address)
            derivation_path: BIP32 path used to derive the HMAC key on device
            chain_id: Chain ID for the network
            contact_scope: Scope/namespace for the identifier (max 32 chars, optional)

        Returns:
            Complete TLV payload bytes.
        """
        assert contact_name and len(contact_name) <= 32, "Contact name required (max 32 chars)"
        assert len(contact_id) == 16, "contact_id must be exactly 16 bytes"
        assert len(identifier) > 0, "Identifier is required"
        assert derivation_path, "Derivation path is required"
        assert chain_id > 0, "Chain ID must be greater than 0"

        path_bytes = pack_derivation_path(derivation_path)

        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, AddressBookResponseType.TYPE_REGISTER_IDENTITY)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.CONTACT_NAME, contact_name.encode('utf-8'))
        if contact_scope:
            payload += self.serialize_field(FieldTag.CONTACT_SCOPE, contact_scope.encode('utf-8'))
        payload += self.serialize_field(FieldTag.IDENTIFIER, identifier)
        payload += self.serialize_field(FieldTag.CONTACT_ID, contact_id)
        payload += self.serialize_field(FieldTag.DERIVATION_PATH, path_bytes)
        payload += self.serialize_field(FieldTag.CHAIN_ID, chain_id)
        payload += self.serialize_field(FieldTag.BLOCKCHAIN_FAMILY, 1)  # Ethereum
        return payload
