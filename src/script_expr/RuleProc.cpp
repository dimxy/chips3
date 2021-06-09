// test script extension processor

#include "uint256.h"
#include "sync.h"
#include "chain.h"
#include "validation.h"
#include "utilstrencodings.h"
#include "streams.h"
#include "serialize.h"
#include "script/cc.h"
#include <crypto/sha256.h>

#include "script/serverchecker.h"
#include "cc/eval.h"

#include "gmp.h"

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

/*
cparse::packToken get_eval(cparse::TokenMap scope)
{
    cparse::TokenMap obj_eval = BASE_eval.getChild();

    obj_eval[PTR_EVAL] = scope[PTR_EVAL];

    return obj_eval;
}
*/


cparse::packToken get_transaction_as_TokenMap(const CTransaction &tx)
{
    cparse::TokenMap txMap = BASE_tx.getChild();

    cparse::TokenList mvins;
    for (auto const &vin : tx.vin) {
        cparse::TokenMap mvin;
        mvin["hash"] = vin.prevout.hash.GetHex();
        mvin["n"] = (int64_t)vin.prevout.n;
        cparse::TokenMap mscriptSig; 
        mscriptSig["isCC"] = vin.scriptSig.IsPayToCryptoCondition();
        mscriptSig["data"] = HexStr(vin.scriptSig.data(), vin.scriptSig.data() + vin.scriptSig.size());
        mvin["scriptSig"] = mscriptSig;
        mvins.push(mvin);
    }

    cparse::TokenList mvouts;
    for (auto const &vout : tx.vout) {
        cparse::TokenMap mvout;
        mvout["nValue"] = vout.nValue;
        cparse::TokenMap mspk; 
        mspk["data"] = HexStr(vout.scriptPubKey.data(), vout.scriptPubKey.data() + vout.scriptPubKey.size());
        mspk["isCC"] = vout.scriptPubKey.IsPayToCryptoCondition();
        mvout["scriptPubKey"] = mspk;
        //mvout["isCC"] = vout.scriptPubKey.IsPayToCryptoCondition();
        mvouts.push(mvout);
    }

    txMap["vin"] = mvins;
    txMap["vout"] = mvouts;

    uint256 dummytxid;
    std::vector<uint8_t> dummydata;
    txMap["lockTime"] = (int64_t)tx.nLockTime; 
    txMap["funcid"] = 'F'; 
    txMap["data"] = HexStr(E_MARSHAL(ss << tx));
    //obj_tx[PTR_TX] = reinterpret_cast<int64_t>(&tx);

    return txMap;
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

cparse::packToken sha256_for_hexstr(cparse::TokenMap scope)
{
    std::string hex = scope["hex"].asString();

    uint256 entropy;
    entropy.SetHex(hex);
    if (entropy.IsNull()) {
        std::cerr << __func__ << " could not parse source string to uint256=" << hex << std::endl;
        return std::string();
    }

    
    CSHA256 sha;
    vuint8_t hash32;
    hash32.resize(CSHA256::OUTPUT_SIZE);
    sha.Write(entropy.begin(), entropy.size());
    sha.Finalize(hash32.data());
    uint256 hentropy(hash32);
   
    std::cerr << __func__ << " sourcehex=" << hex << " result hentropy=" << hentropy.GetHex() << std::endl;
    return hentropy.GetHex();
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
    std::cerr << __func__ << " printing map:" << std::endl;
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
 * "{funcid:C,height:I,amount:V,bytes:B,mystr:S,txid:H,myarray:A{prevtxid:H,prevheight:I}}"
 */
static cparse::packToken decode_script(const vuint8_t vdata, const std::string &desc)
{
    std::cerr << __func__ << " script=" << HexStr(vdata) << " desc=" << desc << std::endl;
    cparse::TokenMap scriptMap;
    CDataStream ss(vdata, SER_NETWORK, PROTOCOL_VERSION);

    std::string::const_iterator ic = desc.begin();

    std::function<void(cparse::TokenMap&, std::string::const_iterator &)> UnserializeScript = [&](cparse::TokenMap &tmap, std::string::const_iterator &ic)
    {
        while(ic != desc.end() && isspace(*ic)) ++ic;
        if (ic == desc.end())  
            throw std::ios_base::failure("UnserializeScript(): unexpected eof in script description");
        if (*ic != '{') 
            throw std::ios_base::failure("UnserializeScript(): expected '{' in script description"); 
        ++ ic;

        while(true) {
            while(ic != desc.end() && isspace(*ic)) ++ic;
            if (ic == desc.end())  
                throw std::ios_base::failure("UnserializeScript(): unexpected eof in script description");

            std::string fieldName;
            while (ic != desc.end() && isalnum(*ic))  {
                fieldName += *ic;
                ++ ic;
            }
            if (ic == desc.end())  
                throw std::ios_base::failure("UnserializeScript(): unexpected eof in script description");
            if (fieldName.empty())  
                throw std::ios_base::failure("UnserializeScript(): field name empty in script description");
            while(ic != desc.end() && isspace(*ic)) ++ic;
            if (*ic != ':') 
                throw std::ios_base::failure("UnserializeScript(): expected ':' in script description");
            ++ ic;
            while(ic != desc.end() && isspace(*ic)) ++ic;
            if (ic == desc.end())  
                throw std::ios_base::failure("UnserializeScript(): unexpected eof in script description");

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
                while(ic != desc.end() && isspace(*ic)) ++ic;
                if (ic == desc.end())  
                    throw std::ios_base::failure("UnserializeScript(): unexpected eof in script description");
                uint64_t asize = ReadCompactSize(ss);
                std::string::const_iterator ic_saved = ic;
                for(int i = 0; i < (int)asize; i ++)
                {
                    cparse::TokenMap nestedMap;
                    ic = ic_saved;  // reset point to arra descitption to use it for next element
                    UnserializeScript(nestedMap, ic);
                    listMaps.push(nestedMap);
                }
                tmap[fieldName] = listMaps;
            }
            else {
                throw std::ios_base::failure("UnserializeScript(): unknown type in script description");
            }
            //++ ic;
            //std::cerr << __func__ << " ic=" << std::string(ic, desc.end()) << std::endl;
            while(ic != desc.end() && isspace(*ic)) ++ic;
            if (ic == desc.end())  
                throw std::ios_base::failure("UnserializeScript(): unexpected eof in script description");    
            if (*ic == '}') 
                break;    
            if (*ic != ',') 
                throw std::ios_base::failure("UnserializeScript(): expected ',' in script description");    
            ++ ic;         
        }
        ++ ic; 
        while(ic != desc.end() && isspace(*ic)) ++ ic;
    };

    try   
    {
        UnserializeScript(scriptMap, ic);
        print_map(scriptMap);
    }
    catch (std::ios_base::failure e)   {
        std::cerr << __func__ << " script decode error: " << e.what() << std::endl;
        return cparse::packToken();
    }
    catch (std::exception e)   {
        std::cerr << __func__ << " script decode error: " << e.what() << std::endl;
        return cparse::packToken();
    }

    if (ic != desc.end())  {
        std::cerr << __func__ << " unexpected symbol in script description: " << *ic << std::endl;
        return cparse::packToken();
    }
    if (!ss.eof())  {
        std::cerr << __func__ << " script data left, in_avail()= " << ss.in_avail() << std::endl;
        return cparse::packToken();
    }
    return scriptMap;
}

cparse::packToken decode_OpReturn(cparse::TokenMap scope)
{
    //std::cerr << __func__ << " entered..." << std::endl;

    cparse::TokenMap txMap = scope["txMap"].asMap();
    std::string desc = scope["desc"].asString();
    cparse::TokenList vouts = txMap["vout"].asList();
    if (vouts.list().size() == 0)  {
        std::cerr << __func__ << " opreturn parse error: no vouts" << std::endl;
        return cparse::packToken();
    }

    cparse::TokenMap spkMap = vouts.list().back().asMap()["scriptPubKey"].asMap();
    vuint8_t vspk = ParseHex(spkMap["data"].asString());
    CScript spk(vspk.begin(), vspk.end());
    std::cerr << __func__ << " vouts.list()=" << vouts.list().size() << " desc=" << desc << std::endl;
    //std::cerr << __func__ << " spk.size()=" << spk.size() << " spk.data=" << spkMap["data"].asString() << std::endl;

    vuint8_t vdata;
    if (!GetOpReturnData(spk, vdata))   {
        std::cerr << __func__ << " opreturn parse error: last vout not opreturn" << std::endl;
        return cparse::packToken();
    }
    return decode_script(vdata, desc);  
}

cparse::packToken decode_ScriptSig(cparse::TokenMap scope)
{
    //std::cerr << __func__ << " entered..." << std::endl;

    cparse::TokenMap scriptSigMap = scope["scriptSig"].asMap();
    //CScript *pscriptSig = reinterpret_cast<CScript*>( scriptSigMap[PTR_SCRIPTSIG].asInt() );
    vuint8_t vsig = ParseHex(scriptSigMap["data"].asString());
    CScript scriptSig(vsig.begin(), vsig.end());
    std::string desc = scope["desc"].asString();    
    std::cerr << __func__ << " vsig.size()=" << scriptSig.size() << " data=" << scriptSigMap["data"].asString() << std::endl;


    vuint8_t vdata;
    GetPushData(scriptSig, vdata);
    return decode_script(vdata, desc);  
}

bool Getscriptaddress(char *destaddr,const CScript &scriptPubKey);

cparse::packToken get_tx_outputs_for_scriptPubKey(cparse::TokenMap scope)
{
    std::cerr << __func__ << " entered..." << std::endl;

    cparse::TokenMap txMap = scope["txMap"].asMap();
    cparse::TokenList vouts = txMap["vout"].asList();
    if (vouts.list().size() == 0)  {
        std::cerr << __func__ << "no vouts" << std::endl;
        return 0;
    }
    CScript checkspk(ParseHex(scope["spk"].asMap()["data"].asString()));
    //char checkaddr[64];
    //Getscriptaddress(checkaddr, checkspk);

    CAmount outputs = 0L;
    for (auto const & v : vouts.list()) {
        CScript spk(ParseHex(v.asMap()["scriptPubKey"].asMap()["data"].asString())); 
        //char voutaddr[64];
        //Getscriptaddress(voutaddr, spk);  
        //std::cerr << __func__ << " checkaddr=" << checkaddr << " voutaddr=" << voutaddr << std::endl;      
        //if (std::string(checkaddr) == std::string(voutaddr)) {
        if (checkspk == spk)  {
            outputs += v.asMap()["nValue"].asInt();
            std::cerr << __func__ << " adding output=" << v.asMap()["nValue"].asInt() << std::endl;
        }
    }
    std::cerr << __func__ << " outputs=" << outputs << std::endl;
    return outputs;  
}

cparse::packToken my_str_cmp(cparse::TokenMap scope)
{
    std::cerr << __func__ << " entered..." << std::endl;

    std::string str1 = scope["str1"].asString();
    std::string str2 = scope["str2"].asString();

    int res = str1.compare(str2);  
    std::cerr << __func__ << " result=" << res << std::endl;
    return res;
}


cparse::packToken is_vin_signed_with_pubkey(cparse::TokenMap scope)
{
    std::cerr << __func__ << " entered..." << std::endl;

    //std::cerr << __func__ << " scope[\"txMap\"]" << scope["txMap"].asString() << std::endl;
    cparse::TokenMap txMap = scope["txMap"].asMap();
    uint32_t ivin = scope["ivin"].asInt();
    vuint8_t vpubkey = ParseHex(scope["pubkey"].asString());
    vuint8_t txdata = ParseHex(txMap["data"].asString());

    //std::cerr << __func__ << " vpubkey=" << HexStr(vpubkey) << std::endl;
    CMutableTransaction mtx; 
    CTransactionRef pvintx;
    uint256 hashBlock;
    E_UNMARSHAL(txdata, ss >> mtx);
    CTransaction tx(mtx);
    //std::cerr << __func__ << " unmarshaled tx=" << HexStr(E_MARSHAL(ss << tx)) << std::endl;
    if (ivin < tx.vin.size() &&
        GetTransaction(tx.vin[ivin].prevout.hash, pvintx, Params().GetConsensus(), hashBlock, true))  {
        PrecomputedTransactionData txdata(tx);
        auto checker = ServerTransactionSignatureChecker(&tx, ivin, pvintx->vout[tx.vin[ivin].prevout.n].nValue, false, txdata);
        const CScript &scriptSig = tx.vin[ivin].scriptSig;
        auto pc = scriptSig.begin();
        opcodetype opcode;
        vuint8_t vsig;

        //std::cerr << __func__ << " scriptSig=" << HexStr(vuint8_t(scriptSig.data(), scriptSig.data()+scriptSig.size())) << std::endl;
        while(scriptSig.GetOp(pc, opcode, vsig)) {
            //std::cerr << __func__ << " opcode=" << (int)opcode << " vsig=" << HexStr(vsig) << std::endl;
            if (!vsig.empty())  {
                bool result = checker.CheckSig(vsig, vpubkey, pvintx->vout[tx.vin[ivin].prevout.n].scriptPubKey, SigVersion::BASE); // which sigversion?
                std::cerr << __func__ << " checker.CheckSig=" << result << std::endl;
                if (result)
                    return result;
            }
        }
    }
    std::cerr << __func__ << " exits with false" << std::endl;
    return false;
}


// normalise uint256 to the 0...norm values
cparse::packToken normalize_uint256(cparse::TokenMap scope)
{
    std::cerr << __func__ << " entered..." << std::endl;

    std::string u256hex = scope["u256hex"].asString();
    uint256 u256value;
    u256value.SetHex(u256hex);
    int32_t norm = scope["norm"].asInt();

    mpz_t mpzValue;
    mpz_t mpzMax;
    mpz_t mpzResult;


    mpz_init(mpzValue);
    mpz_init(mpzMax);
    mpz_init(mpzResult);

    mpz_import(mpzValue, 1, 1, sizeof(u256value), 0, 0, &u256value);
    mpz_set_ui(mpzMax, 1);
    mpz_ui_pow_ui(mpzMax, 2, sizeof(u256value)*8); // get 0x10...00 (256) val
    mpz_mul_si(mpzResult, mpzValue, norm);
    mpz_div(mpzResult, mpzResult, mpzMax);

    int32_t iResult = mpz_get_si(mpzResult);

    mpz_clear(mpzValue);
    mpz_clear(mpzMax);
    mpz_clear(mpzResult);

    std::cerr << __func__ << " exits normalised value=" << iResult << std::endl;
    return iResult;
}

cparse::packToken print_to_stderr(cparse::TokenMap scope)
{
    cparse::packToken name = scope["name"];
    cparse::packToken val = scope["value"];

    std::cerr << __func__ << " type=" << (int)val->type << " ";
    if (name->type == cparse::STR)
        std::cerr << name.asString() << " ";

    if (val->type == cparse::STR)
        std::cerr << val.asString();
    else if (val->type == cparse::INT)
        std::cerr << val.asInt();
    else if (val->type == cparse::BOOL)
        std::cerr << val.asBool();
    else if (val->type == cparse::REAL)
        std::cerr << val.asDouble();
    std::cerr << std::endl;
    return cparse::packToken();
}

void CRuleProc::init()
{
    std::cerr << "CRuleProc::init enterred" << std::endl;
    scope[CHAIN_ACTIVE] = get_active_chain();  // cparse::CppFunction(&get_active_chain, {}, "");
    scope["GetTransaction"] = cparse::CppFunction(&get_transaction, {"hash"}, "");
    scope["DecodeOpReturn"] = cparse::CppFunction(&decode_OpReturn, {"txMap", "desc"}, "");
    scope["DecodeScriptSig"] = cparse::CppFunction(&decode_ScriptSig, {"scriptSig", "desc"}, "");
    scope["OutputsForScriptPubKey"] = cparse::CppFunction(&get_tx_outputs_for_scriptPubKey, {"txMap", "spk"}, "");
    scope["StrCmp"] = cparse::CppFunction(&my_str_cmp, {"str1", "str2"}, "");

    scope["Sha256"] = cparse::CppFunction(&sha256_for_hexstr, {"hex"}, "");
    scope["IsSigner"] = cparse::CppFunction(&is_vin_signed_with_pubkey, {"txMap", "ivin", "pubkey"}, "");
    scope["Norm256"] = cparse::CppFunction(&normalize_uint256, {"u256hex", "norm"}, "");
    scope["Print"] = cparse::CppFunction(&print_to_stderr, {"name", "value"}, "");



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

int CRuleProc::eval(const std::string &expr, const CTransaction &tx, int32_t nIn, std::string &error)
{
    ruleparser::RuleStatement ruleParser;

    scope[EVAL_TX] = get_transaction_as_TokenMap(tx); // convert eval tx into map and put it into rule scope
    scope[I_VIN] = nIn; // convert eval tx into map and put it into rule scope

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
    inputScope["desc"] = desc;
    cparse::TokenMap parsed = decode_OpReturn(inputScope).asMap();

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