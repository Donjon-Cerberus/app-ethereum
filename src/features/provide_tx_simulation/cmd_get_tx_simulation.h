#pragma once

#ifdef HAVE_TRANSACTION_CHECKS

#include <stdint.h>
#include <stdbool.h>
#include "common_utils.h"
#include "os_pki.h"
#include "tlv_use_case_transaction_check.h"

// Ethereum-specific struct with EVM-fixed-size address field
typedef struct tx_simu_s {
    uint64_t chain_id;
    uint8_t tx_hash[TRANSACTION_CHECK_HASH_SIZE];
    uint8_t domain_hash[TRANSACTION_CHECK_HASH_SIZE];
    char provider_msg[TRANSACTION_CHECK_MSG_SIZE + 1];
    char tiny_url[TRANSACTION_CHECK_URL_SIZE + 1];
    uint8_t address[ADDRESS_LENGTH];
    char partner[TRANSACTION_CHECK_PARTNER_SIZE];
    transaction_check_risk_t risk;
    transaction_check_type_t type;
    transaction_check_category_t category;
} tx_simulation_t;

_Static_assert(CERTIFICATE_TRUSTED_NAME_MAXLEN > TRANSACTION_CHECK_PARTNER_SIZE - 1,
               "Partner size is too big to get the trusted name");

uint16_t handle_tx_simulation(uint8_t p1,
                              uint8_t p2,
                              const uint8_t *data,
                              uint8_t length,
                              unsigned int *flags);
void handle_tx_simulation_opt_in(bool response_expected);
void ui_tx_simulation_opt_in(bool response_expected);

void clear_tx_simulation(void);
void set_tx_simulation_warning(void);

const char *get_tx_simulation_risk_str(void);
const char *get_tx_simulation_category_str(void);

#endif  // HAVE_TRANSACTION_CHECKS

const char *ui_tx_simulation_finish_str(void);
