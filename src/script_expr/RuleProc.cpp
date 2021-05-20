// test script extension processor

#include "uint256.h"
#include "sync.h"
#include "chain.h"
#include "validation.h"
#include "utilstrencodings.h"
#include "streams.h"
#include "serialize.h"
#include "script/cc.h"

#include "cc/eval.h"


#include "RuleParser.h"
#include "RuleProc.h"

struct ruleparser::RuleParserStartup parserStartup; // init code parser


cparse::TokenMap BASE_chain;
cparse::TokenMap BASE_eval;
cparse::TokenMap BASE_tx;
cparse::TokenMap BASE_vin;
cparse::TokenMap BASE_vout;

cparse::packToken get_chain_height(cparse::TokenMap scope)
{
    // Create a child of the BASE class:
    cparse::TokenMap _this = scope["this"].asMap();
    CChain *pChain = reinterpret_cast<CChain *>(_this[PTR_CHAIN].asInt());

    AssertLockHeld(cs_main);
    return pChain->Height();
}

cparse::packToken get_active_chain()
{
    // Create a child of the BASE class:
    cparse::TokenMap obj_chain = BASE_chain.getChild();

    obj_chain[PTR_CHAIN] = reinterpret_cast<int64_t>(&chainActive);
    obj_chain["height"] = cparse::CppFunction(&get_chain_height);

    return obj_chain;
}

cparse::packToken get_eval(cparse::TokenMap scope)
{
    cparse::TokenMap obj_eval = BASE_eval.getChild();

    obj_eval[PTR_EVAL] = scope[PTR_EVAL];

    return obj_eval;
}


cparse::packToken get_transaction_as_TokenMap(const CTransaction &tx)
{
    cparse::TokenMap obj_tx = BASE_tx.getChild();

    cparse::TokenList mvins;
    for (auto const &vin : tx.vin) {
        cparse::TokenMap mvin;
        mvin["hash"] = vin.prevout.hash.GetHex();
        mvin["n"] = (int64_t)vin.prevout.n;
        cparse::TokenMap mscriptSig; 
        mscriptSig["isCC"] = vin.scriptSig.IsPayToCryptoCondition();
        mscriptSig[PTR_SCRIPTSIG] = reinterpret_cast<int64_t>(&vin.scriptSig);
        mvin["scriptSig"] = mscriptSig;
        mvins.push(mvin);
    }

    cparse::TokenList mvouts;
    for (auto const &vout : tx.vout) {
        cparse::TokenMap mvout;
        mvout["nValue"] = vout.nValue;
        cparse::TokenMap mspk; 
        mspk[PTR_SCRIPTPUBKEY] = reinterpret_cast<int64_t>(&vout.scriptPubKey);
        mspk["isCC"] = vout.scriptPubKey.IsPayToCryptoCondition();
        mvout["scriptPubKey"] = mspk;
        //mvout["isCC"] = vout.scriptPubKey.IsPayToCryptoCondition();
        mvouts.push(mvout);
    }

    obj_tx["vin"] = mvins;
    obj_tx["vout"] = mvouts;

    uint256 dummytxid;
    std::vector<uint8_t> dummydata;
    obj_tx["funcid"] = 'F'; //std::string(1, DecodeCCVMSampleInstanceOpRet(tx.vout.back().scriptPubKey, dummytxid, dummydata));
    obj_tx[PTR_TX] = reinterpret_cast<int64_t>(&tx);

    return obj_tx;
}

cparse::packToken get_transaction(cparse::TokenMap scope)
{
    //std::cerr << __func__ << " entered..." << std::endl;
    uint256 hash = uint256S( scope["hash"].asString().c_str() );

    cparse::packToken ttx;
    uint256 hashBlock;
    CTransactionRef tx;
    if (GetTransaction(hash, tx, Params().GetConsensus(), hashBlock, true)) {
        ttx = get_transaction_as_TokenMap(*tx);
        ttx[TX_BLOCKHASH] = hashBlock.GetHex();
        std::cerr << __func__ << " tx.vout.size=" << tx->vout.size() << std::endl;
        if (tx->vout.size() > 0)
            std::cerr << __func__ << " tx.vout[0].nValue=" << tx->vout[0].nValue << std::endl;
    }
    return ttx;
}

cparse::packToken get_tx_height(cparse::TokenMap scope)
{
    cparse::TokenMap _this = scope["this"].asMap();

    uint256 hashBlock = uint256( ParseHex(_this[TX_BLOCKHASH].asString().c_str()) ); // get stored block hash

    BlockMap::const_iterator it = mapBlockIndex.find(hashBlock);
    return it != mapBlockIndex.end() ? it->second->nHeight : -1;
}

/*
cparse::packToken get_eval_tx(cparse::TokenMap scope)
{
    cparse::TokenMap obj_tx = BASE_tx.getChild();

    CTransaction *ptx = reinterpret_cast<CTransaction *>( (*scope.parent())[PTR_EVAL_TX].asInt() ); // set to eval tx ptr already in the scope
    std::cerr << __func__ << " ptx->vin.size=" << ptx->vin.size() << " ptx->vout.size=" << ptx->vout.size() << std::endl;

    return get_transaction_as_TokenMap(*ptx);
}*/


void print_map(cparse::TokenMap m) 
{
    for (auto e = m.map().begin(); e != m.map().end(); e++)  {
        std::cerr << "    " << e->first;
        switch(e->second.token()->type) 
        {
            case cparse::STR: 
                std::cerr << " " << e->second.asString();
                break;
            case cparse::INT: 
                std::cerr << " " << e->second.asInt();
                break;
            case cparse::LIST: 
                std::cerr << std::endl;
                for (auto l = e->second.asList().list().begin(); l != e->second.asList().list().end(); l++)  {
                    print_map(l->asMap());
                }
                break;
            default:
                std::cerr << " unknown type=" << e->second.token()->type;
        }
        std::cerr << std::endl;
    }
}


/**
 * access opreturn in txMap and decode it according to the description passed in 'opreturnDesc'  
 * the description format example (be carefull, it might look like a json but it's not a json object):
 * "{funcid:C,height:I,amount:V,mystr:S,txid:H,myarray:A{prevtxid:H,prevheight:I}}"
 */
cparse::packToken decode_opreturn(cparse::TokenMap scope)
{
    //std::cerr << __func__ << " entered..." << std::endl;

    cparse::TokenMap txMap = scope["txMap"].asMap();
    std::string opretDesc = scope["opreturnDesc"].asString();
    cparse::TokenList vouts = txMap["vout"].asList();
    if (vouts.list().size() == 0)  {
        std::cerr << __func__ << " opreturn parse error: no vouts" << std::endl;
        return cparse::packToken();
    }
    CScript *pspk = reinterpret_cast<CScript*>( vouts.list().back().asMap()["scriptPubKey"].asMap()[PTR_SCRIPTPUBKEY].asInt() );

    vuint8_t vdata;
    if (!GetOpReturnData(*pspk, vdata))   {
        std::cerr << __func__ << " opreturn parse error: last vout not opreturn" << std::endl;
        return cparse::packToken();
    }

    cparse::TokenMap opretMap;
    CDataStream ss(vdata, SER_NETWORK, PROTOCOL_VERSION);

    std::string::iterator ic = opretDesc.begin();

    std::function<void(cparse::TokenMap&, std::string::iterator &)> UnserializeOpreturn = [&](cparse::TokenMap &tmap, std::string::iterator &ic)
    {
        while(ic != opretDesc.end() && isspace(*ic)) ++ic;
        if (ic == opretDesc.end())  
            throw std::ios_base::failure("UnserializeOpreturn(): unexpected eof in opreturn description");
        if (*ic != '{') 
            throw std::ios_base::failure("UnserializeOpreturn(): expected '{' in opreturn description"); 
        ++ ic;

        while(true) {
            while(ic != opretDesc.end() && isspace(*ic)) ++ic;
            if (ic == opretDesc.end())  
                throw std::ios_base::failure("UnserializeOpreturn(): unexpected eof in opreturn description");

            std::string fieldName;
            while (ic != opretDesc.end() && isalnum(*ic))  {
                fieldName += *ic;
                ++ ic;
            }
            if (ic == opretDesc.end())  
                throw std::ios_base::failure("UnserializeOpreturn(): unexpected eof in opreturn description");
            if (fieldName.empty())  
                throw std::ios_base::failure("UnserializeOpreturn(): field name empty in opreturn description");
            while(ic != opretDesc.end() && isspace(*ic)) ++ic;
            if (*ic != ':') 
                throw std::ios_base::failure("UnserializeOpreturn(): expected ':' in opreturn description");
            ++ ic;
            while(ic != opretDesc.end() && isspace(*ic)) ++ic;
            if (ic == opretDesc.end())  
                throw std::ios_base::failure("UnserializeOpreturn(): unexpected eof in opreturn description");

            if (*ic == 'C')  {
                char c;
                Unserialize(ss, c);
                tmap[fieldName] = std::string(1, c);
                ++ ic;
            } else if (*ic == 'I')  {
                int32_t i;
                Unserialize(ss, i);
                tmap[fieldName] = i;
                ++ ic;
            } else if (*ic == 'V')  {
                CAmount v;
                Unserialize(ss, v);
                tmap[fieldName] = v;
                ++ ic;
            } else if (*ic == 'H')  {
                uint256 v;
                Unserialize(ss, v);
                tmap[fieldName] = v.GetHex();
                ++ ic;
            } else if (*ic == 'S')  {
                std::string s;
                Unserialize(ss, s);
                tmap[fieldName] = s;
                ++ ic;
            } else if (*ic == 'B')  {
                vuint8_t ba;
                Unserialize(ss, ba);
                tmap[fieldName] = HexStr(ba);
                ++ ic;
            } else if (*ic == 'A')  {
                cparse::TokenList listMaps;
                ++ ic;
                while(ic != opretDesc.end() && isspace(*ic)) ++ic;
                if (ic == opretDesc.end())  
                    throw std::ios_base::failure("UnserializeOpreturn(): unexpected eof in opreturn description");
                uint64_t asize = ReadCompactSize(ss);
                std::string::iterator ic_saved = ic;
                for(int i = 0; i < (int)asize; i ++)
                {
                    cparse::TokenMap nestedMap;
                    ic = ic_saved;  // reset point to arra descitption to use it for next element
                    UnserializeOpreturn(nestedMap, ic);
                    listMaps.push(nestedMap);
                }
                tmap[fieldName] = listMaps;
            }
            else {
                throw std::ios_base::failure("UnserializeOpreturn(): unknown type in opreturn description");
            }
            //++ ic;
            //std::cerr << __func__ << " ic=" << std::string(ic, opretDesc.end()) << std::endl;
            while(ic != opretDesc.end() && isspace(*ic)) ++ic;
            if (ic == opretDesc.end())  
                throw std::ios_base::failure("UnserializeOpreturn(): unexpected eof in opreturn description");    
            if (*ic == '}') 
                break;    
            if (*ic != ',') 
                throw std::ios_base::failure("UnserializeOpreturn(): expected ',' in opreturn description");    
            ++ ic;         
        }
        ++ ic; 
        while(ic != opretDesc.end() && isspace(*ic)) ++ ic;
    };

    try   
    {
        UnserializeOpreturn(opretMap, ic);

        print_map(opretMap);
    }
    catch (std::ios_base::failure e)   {
        std::cerr << __func__ << " opreturn decode error: " << e.what() << std::endl;
        return cparse::packToken();
    }
    catch (std::exception e)   {
        std::cerr << __func__ << " opreturn decode error: " << e.what() << std::endl;
        return cparse::packToken();
    }

    if (ic != opretDesc.end())  {
        std::cerr << __func__ << " unexpected symbol in opreturn description: " << *ic << std::endl;
        return cparse::packToken();
    }
    if (!ss.eof())  {
        std::cerr << __func__ << " opreturn data left, in_avail()= " << ss.in_avail() << std::endl;
        return cparse::packToken();
    }
    return opretMap;
}


void CRuleProc::init()
{
    std::cerr << "CRuleProc::init enterred" << std::endl;
    scope[CHAIN_ACTIVE] = get_active_chain();  // cparse::CppFunction(&get_active_chain, {}, "");
    scope["GetTransaction"] = cparse::CppFunction(&get_transaction, {"hash"}, "");
    scope["DecodeOpReturn"] = cparse::CppFunction(&decode_opreturn, {"txMap", "opreturnDesc"}, "");


    //BASE_chain["height"] = cparse::CppFunction(&get_chain_height);

    //scope["getEval"] = cparse::CppFunction(&get_eval);
    //scope["getEvalTx"] = cparse::CppFunction(&get_eval_tx);
    //BASE_tx["vin"] = cparse::CppFunction(&get_tx_vin, {"index"}, "");
    //BASE_vin["hash"] = cparse::CppFunction(&get_tx_vin_hash, {}, "");
    //BASE_tx["vout"] = cparse::CppFunction(&get_tx_vout, {"index"}, "");
    //BASE_vout["amount"] = cparse::CppFunction(&get_tx_vout_amount, {}, "");

    BASE_tx["height"] = cparse::CppFunction(&get_tx_height);  // tx.height()

}

int CRuleProc::compile(const std::string &expr, std::string &error)
{
    ruleparser::RuleStatement ruleParser;

    std::cerr << "CRuleProc::compile txrule expression=" << expr << std::endl;

    try {
        const char *rest;
        ruleParser.compile(expr.c_str(), &rest);

        // check the rest of the string:
        while(isspace(*rest)) ++rest;
        if (*rest)  {
            std::cerr << "CRuleProc::compile txrule parse error: unknown character: " << *rest << " (" << (int)*rest << ")"  << std::endl;
            error = std::string("txrule parse error: unknown character: ") + *rest;
            return RULE_ERROR;
        }
    } catch(cparse::msg_exception e)  {
        std::cerr << "CRuleProc::compile could not parse txrule: " << e.what() << std::endl;
        error = std::string("txrule syntax error: ") + e.what();
        return RULE_ERROR;
    }
    return RULE_OKAY;
}

int CRuleProc::eval(const std::string &expr, const CTransaction &tx, std::string &error)
{
    ruleparser::RuleStatement ruleParser;

    scope[EVAL_TX] = get_transaction_as_TokenMap(tx); // convert eval tx into map and put it into rule scope
    int result = RULE_INVALID;

    std::cerr << "CRuleProc::eval txrule expression=" << expr << std::endl;

    try {
        const char *rest;
        ruleParser.compile(expr.c_str(), &rest);

        // check the rest of the string:
        while(isspace(*rest)) ++rest;
        if (*rest)  {
            std::cerr << "CRuleProc::compile txrule parse error: unknown character: " << *rest << " (" << (int)*rest << ")"  << std::endl;
            error = std::string("txrule parse error: unknown character: ") + *rest;
            return RULE_ERROR;
        }
    } catch(cparse::msg_exception e)  {
        std::cerr << "CRuleProc::compile could not parse txrule: " << e.what() << std::endl;
        error = std::string("txrule syntax error: ") + e.what();
        return RULE_ERROR;
    }


    try {
        result = ruleParser.exec(scope).asBool() ? RULE_OKAY : RULE_INVALID;
    } catch(cparse::msg_exception e)  {
        std::cerr << "CRuleProc::eval error evaluating txrule: " << e.what() << std::endl;
        error = std::string("error evaluating txrule: ") + e.what();
        return RULE_ERROR;
    }
    //std::cerr << "CRuleProc::eval txrule result=" << result << std::endl;

    if (result == RULE_OKAY) 
        std::cerr << "CRuleProc::eval txrule validation okay" << std::endl;
    else  {
        std::cerr << "CRuleProc::eval txrule validation failed" << std::endl;
        error = std::string("txrule invalid");
    }

    return result;
}

void test_decode_opret(const CTransaction &tx, std::string desc)
{
    cparse::TokenMap inputScope;

    inputScope["txMap"] = get_transaction_as_TokenMap(tx);
    inputScope["opreturnDesc"] = desc;
    cparse::TokenMap parsed = decode_opreturn(inputScope).asMap();

    try {
        std::cerr << __func__ << " parsed map:" << std::endl;
        print_map(parsed);
    }
    catch(std::exception e)
    {
        std::cerr << __func__ << " print map exception: " << e.what() << std::endl;
    }
}

void run_test_decode_opreturn()
{

    CMutableTransaction mtx;
    CScript opret;
    uint8_t funcid = 'F';
    std::string name = "hello";
    vuint8_t pk = ParseHex("02f3578fbc0fc76056eae34180a71e9190ee08ad05d40947aab7a286666e2ce798");

    std::vector<std::pair<int32_t, uint256>> myarr = {
        { 1, uint256S("00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931") },
        { 2, uint256S("0x00000010892de4ff2aac1bc7cff0d2b001caf66ca160fd47c1290dc8a49bab2c") },
    };

    uint64_t asize = myarr.size();
    opret << OP_RETURN << E_MARSHAL(ss << funcid << pk << name << VARINT(asize); 
        for(auto p : myarr)
            ss << p.first << p.second;
    );
    mtx.vout.push_back(CTxOut(0, opret));

    test_decode_opret(mtx, "{funcid:C,pk:B,name:S,myarr:A{myint:I,myhash:H,a:I }}");
    //test_decode_opret(mtx, "{funcid:C,pk:B,name:S}");

}

void run_test_decode_opreturn2(CScript opret, std::string desc)
{

    CMutableTransaction mtx;

    mtx.vout.push_back(CTxOut(0, opret));

    test_decode_opret(mtx, desc);
}