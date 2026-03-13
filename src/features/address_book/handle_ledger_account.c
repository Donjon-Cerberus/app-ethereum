/* SPDX-FileCopyrightText: © 2026 Ledger SAS */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file handle_ledger_account.c
 * @brief Coin-app callbacks for the Register and Rename Ledger Account flows
 *
 * Implements the coin-app callbacks required by the SDK:
 *
 * Register Ledger Account:
 *  - handle_check_ledger_account(): validate the parsed account data
 *  - get_register_ledger_account_tagValue(): populate the NBGL review screen
 *  - get_ledger_account_icon(): return the network icon
 *  - finalize_ui_register_ledger_account(): clean up after user decision
 *
 * Rename Ledger Account:
 *  - handle_check_rename_ledger_account(): validate and store rename params
 *  - get_rename_ledger_account_tagValue(): populate the NBGL review screen
 *  - finalize_ui_rename_ledger_account(): clean up after user decision
 */

#include "ledger_account.h"
#include "chain_config.h"
#include "apdu_constants.h"
#include "common_utils.h"
#include "network.h"
#include "ui_nbgl.h"
#include "ui_callbacks.h"
#include "ui_utils.h"
#include "app_mem_utils.h"
#include "get_public_key.h"
#include "io.h"
#include "ox_ec.h"
#include "network_icons.h"

#if defined(HAVE_ADDRESS_BOOK) && defined(HAVE_ADDRESS_BOOK_LEDGER_ACCOUNT)

/* Private defines -----------------------------------------------------------*/

/* Private types -------------------------------------------------------------*/

/**
 * @brief Context for Register Ledger Account flow
 */
typedef struct {
    char *address_display;
    char *network_display;
} register_ledger_account_ctx_t;

/**
 * @brief Context for Rename Ledger Account flow
 */
typedef struct {
    char *previous_name;
    char *new_name;
    char *network;
} rename_ledger_account_ctx_t;

/**
 * @brief Global context for all Ledger Account-related UI flows
 */
typedef struct {
    ledger_account_t *ledger_account;  // Shared by both flows (for icon)
    union {
        register_ledger_account_ctx_t register_account;
        rename_ledger_account_ctx_t rename_account;
    };
} ledger_account_ui_ctx_t;

/* Private variables ---------------------------------------------------------*/
static ledger_account_ui_ctx_t g_ctx = {0};

/* Exported functions --------------------------------------------------------*/

/**
 * @brief Callback to retrieve the coin icon for the Ledger Account UI.
 *
 * @return Pointer to the icon details structure, or NULL if no icon is available.
 */
const nbgl_icon_details_t *get_ledger_account_icon(void) {
    return get_network_icon_from_chain_id(&g_ctx.ledger_account->chain_id);
}

/* =========================================================================
 * Register Ledger Account callbacks
 * =========================================================================
 */

/**
 * @brief Handle called to finalize the UI flow for registering a Ledger Account
 */
void finalize_ui_register_ledger_account(void) {
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.register_account.address_display);
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.register_account.network_display);
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.ledger_account);
    ui_idle();
}

/**
 * @brief Handle called to validate the received Ledger Account
 *
 * Validates derivation path length and chain ID range for Ethereum.
 *
 * @param[in] params Structure containing the ledger account to validate
 * @return true if the account is valid, false to reject
 */
bool handle_check_ledger_account(ledger_account_t *params) {
    cx_ecfp_public_key_t publicKey = {0};
    char address[ADDRESS_LENGTH_HEX_STR] = {0};
    PRINTF("Inside handle_check_ledger_account\n");
    if (params == NULL) {
        PRINTF("params is NULL\n");
        return false;
    }
    if (params->bip32_path.length == 0 || params->bip32_path.length > MAX_BIP32_PATH) {
        PRINTF("Invalid derivation path length: %d\n", params->bip32_path.length);
        return false;
    }
    if ((params->chain_id > MAX_VALID_CHAIN_ID) || (params->chain_id == 0)) {
        PRINTF("Unsupported chain ID: %llu\n", params->chain_id);
        return false;
    }
    if (get_public_key_string((bip32_path_t *) &params->bip32_path,
                              publicKey.W,
                              address,
                              NULL,
                              params->chain_id) != CX_OK) {
        PRINTF("Failed to get public key\n");
        return false;
    }
    PRINTF("Ledger account validation successful\n");

    g_ctx.ledger_account = APP_MEM_ALLOC(sizeof(ledger_account_t));
    if (g_ctx.ledger_account == NULL) {
        PRINTF("Failed to allocate ledger_account\n");
        return false;
    }
    memmove(g_ctx.ledger_account, params, sizeof(ledger_account_t));
    return true;
}

/**
 * @brief Callback to retrieve a tag-value pair for the Ledger Account review UI
 *
 * Pair 0: contact name
 * Pair 1: network
 * Pair 2: derived Ethereum address
 *
 * @param[in] pairIndex The index of the tag-value pair to retrieve.
 * @return Pointer to the tag-value pair structure, or NULL if the index is invalid.
 */
nbgl_contentTagValue_t *get_register_ledger_account_tagValue(uint8_t pairIndex) {
    static nbgl_contentTagValue_t currentPair = {0};
    cx_ecfp_public_key_t publicKey = {0};

    switch (pairIndex) {
        case 0:
            currentPair.item = "Address name";
            currentPair.value = g_ctx.ledger_account->account_name;
            break;

        case 1:
            g_ctx.register_account.network_display = APP_MEM_ALLOC(MAX_NETWORK_LEN);
            if (g_ctx.register_account.network_display == NULL) {
                PRINTF("Failed to allocate network display buffer\n");
                return NULL;
            }
            if (get_network_as_string_from_chain_id(g_ctx.register_account.network_display,
                                                    MAX_NETWORK_LEN,
                                                    g_ctx.ledger_account->chain_id) == false) {
                PRINTF("Failed to get network name from chain ID\n");
                APP_MEM_FREE_AND_NULL((void **) &g_ctx.register_account.network_display);
                return NULL;
            }
            currentPair.item = "Network";
            currentPair.value = g_ctx.register_account.network_display;
            break;

        case 2:
            g_ctx.register_account.address_display = APP_MEM_ALLOC(ADDRESS_LENGTH_HEX_STR);
            if (g_ctx.register_account.address_display == NULL) {
                PRINTF("Failed to allocate address display buffer\n");
                return NULL;
            }
            g_ctx.register_account.address_display[0] = '0';
            g_ctx.register_account.address_display[1] = 'x';
            if (get_public_key_string((bip32_path_t *) &g_ctx.ledger_account->bip32_path,
                                      publicKey.W,
                                      g_ctx.register_account.address_display + 2,
                                      NULL,
                                      g_ctx.ledger_account->chain_id) != CX_OK) {
                PRINTF("Failed to get public key\n");
                APP_MEM_FREE_AND_NULL((void **) &g_ctx.register_account.address_display);
                return NULL;
            }
            currentPair.item = "Address";
            currentPair.value = g_ctx.register_account.address_display;
            break;

        default:
            PRINTF("Unexpected pair index: %d\n", pairIndex);
            return NULL;
    }
    return &currentPair;
}

/* =========================================================================
 * Rename Ledger Account callbacks
 * =========================================================================
 */

/**
 * @brief Handle called to finalize the UI flow for renaming a Ledger Account.
 */
void finalize_ui_rename_ledger_account(void) {
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.ledger_account);
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.rename_account.previous_name);
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.rename_account.new_name);
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.rename_account.network);
    ui_idle();
}

/**
 * @brief Handle called to validate and store the Rename Ledger Account parameters.
 *
 * Dynamically allocates buffers for display data for use by get_rename_ledger_account_tagValue().
 *
 * @param[in] params Previous name and new ledger account data
 * @return true if the rename is acceptable, false to reject
 */
bool handle_check_rename_ledger_account(const rename_ledger_account_t *params) {
    if (params == NULL) {
        PRINTF("handle_check_rename_ledger_account: NULL parameter\n");
        return false;
    }

    // Allocate and store ledger_account so get_ledger_account_icon() returns the right icon
    g_ctx.ledger_account = APP_MEM_ALLOC(sizeof(ledger_account_t));
    if (g_ctx.ledger_account == NULL) {
        PRINTF("Failed to allocate ledger_account\n");
        return false;
    }
    memmove(g_ctx.ledger_account, &params->ledger_account, sizeof(ledger_account_t));

    // Allocate previous name
    g_ctx.rename_account.previous_name = APP_MEM_ALLOC(ACCOUNT_NAME_LENGTH);
    if (g_ctx.rename_account.previous_name == NULL) {
        PRINTF("Failed to allocate previous_name\n");
        APP_MEM_FREE_AND_NULL((void **) &g_ctx.ledger_account);
        return false;
    }
    strncpy(g_ctx.rename_account.previous_name,
            params->previous_account_name,
            ACCOUNT_NAME_LENGTH - 1);

    // Allocate new name
    g_ctx.rename_account.new_name = APP_MEM_ALLOC(ACCOUNT_NAME_LENGTH);
    if (g_ctx.rename_account.new_name == NULL) {
        PRINTF("Failed to allocate new_name\n");
        APP_MEM_FREE_AND_NULL((void **) &g_ctx.ledger_account);
        APP_MEM_FREE_AND_NULL((void **) &g_ctx.rename_account.previous_name);
        return false;
    }
    strncpy(g_ctx.rename_account.new_name,
            params->ledger_account.account_name,
            ACCOUNT_NAME_LENGTH - 1);

    // Allocate and format network name for Ethereum
    g_ctx.rename_account.network = APP_MEM_ALLOC(MAX_NETWORK_LEN);
    if (g_ctx.rename_account.network == NULL) {
        PRINTF("Failed to allocate network\n");
        APP_MEM_FREE_AND_NULL((void **) &g_ctx.ledger_account);
        APP_MEM_FREE_AND_NULL((void **) &g_ctx.rename_account.previous_name);
        APP_MEM_FREE_AND_NULL((void **) &g_ctx.rename_account.new_name);
        return false;
    }
    if (!get_network_as_string_from_chain_id(g_ctx.rename_account.network,
                                             MAX_NETWORK_LEN,
                                             params->ledger_account.chain_id)) {
        PRINTF("handle_check_rename_ledger_account: failed to get network name\n");
        APP_MEM_FREE_AND_NULL((void **) &g_ctx.ledger_account);
        APP_MEM_FREE_AND_NULL((void **) &g_ctx.rename_account.previous_name);
        APP_MEM_FREE_AND_NULL((void **) &g_ctx.rename_account.new_name);
        APP_MEM_FREE_AND_NULL((void **) &g_ctx.rename_account.network);
        return false;
    }
    return true;
}

/**
 * @brief Callback to retrieve a tag-value pair for the Rename Ledger Account UI.
 *
 * Pair 0: old account name
 * Pair 1: new account name
 * Pair 2: network
 *
 * @param[in] pairIndex The index of the tag-value pair to retrieve.
 * @return Pointer to the tag-value pair structure, or NULL if the index is invalid.
 */
nbgl_contentTagValue_t *get_rename_ledger_account_tagValue(uint8_t pairIndex) {
    static nbgl_contentTagValue_t currentPair = {0};

    switch (pairIndex) {
        case 0:
            currentPair.item = "Previous name";
            currentPair.value = g_ctx.rename_account.previous_name;
            break;
        case 1:
            currentPair.item = "New name";
            currentPair.value = g_ctx.rename_account.new_name;
            break;
        case 2:
            currentPair.item = "Network";
            currentPair.value = g_ctx.rename_account.network;
            break;
        default:
            PRINTF("Unexpected pair index: %d\n", pairIndex);
            return NULL;
    }
    return &currentPair;
}

#endif  // HAVE_ADDRESS_BOOK && HAVE_ADDRESS_BOOK_LEDGER_ACCOUNT
