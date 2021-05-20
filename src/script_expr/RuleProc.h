// test script extension parser
#ifndef __RULEPROC_H__
#define __RULEPROC_H__

#include <iostream>
#include <string>


#include "primitives/block.h"
#include "primitives/transaction.h"
#include <chainparams.h>

#include "RuleParser.h"

// internally stored pointers
#define PTR_EVAL                "eval_ptr"
#define PTR_TX                  "tx_ptr"
#define PTR_EVAL_TX             "eval_tx_ptr"
#define PTR_CHAIN               "chain_ptr"
#define PTR_SCRIPTSIG            "scriptSig_ptr"
#define PTR_SCRIPTPUBKEY         "scriptPubKey_ptr"

// internally stored ojects
#define TX_BLOCKHASH            "block_hash"

// scope exposed objects
#define EVAL_TX                 "evaltx"
#define CHAIN_ACTIVE            "chainActive"

const int RULE_ERROR = -1,
          RULE_INVALID = 0,
          RULE_OKAY = 1;

typedef std::vector<uint8_t> vuint8_t;

class CRuleProc {
public:
    CRuleProc()  { }

    void init();
    int compile(const std::string &expr, std::string &error);
    int eval(const std::string &expr, const CTransaction &tx, std::string &error);

    ruleparser::TokenMap scope;
};

#endif // #ifndef __RULEPROC_H__
