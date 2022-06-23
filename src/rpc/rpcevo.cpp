// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "messagesigner.h"
#include "rpc/server.h"
#include "utilmoneystr.h"
#include "validation.h"

#ifdef ENABLE_WALLET
#include "wallet/coincontrol.h"
#include "wallet/wallet.h"
#include "wallet/rpcwallet.h"
#endif//ENABLE_WALLET

#include "netbase.h"

#include "evo/specialtx.h"
#include "evo/providertx.h"
#include "evo/deterministicmns.h"
#include "evo/simplifiedmns.h"

#include "bls/bls.h"

extern UniValue signrawtransaction(const JSONRPCRequest& request);
extern UniValue sendrawtransaction(const JSONRPCRequest& request);

std::string GetHelpString(int nParamNum, std::string strParamName)
{
    static const std::map<std::string, std::string> mapParamHelp = {
        {"collateralAddress",
            "%d. \"collateralAddress\"        (string, required) The address to send the collateral to.\n"
        },
        {"ipAndPort",
            "%d. \"ipAndPort\"                (string, required) IP and port in the form \"IP:PORT\".\n"
            "                              Must be unique on the network. Can be set to 0, which will require a ProUpServTx afterwards.\n"
        },
        {"operatorPubKey",
            "%d. \"operatorPubKey\"           (string, required) The operator BLS public key. The private key does not have to be known.\n"
            "                              It has to match the private key which is later used when operating the masternode.\n"
        },
        {"ownerAddress",
            "%d. \"ownerAddress\"             (string, required) The address to use for payee updates and proposal voting.\n"
            "                              The private key belonging to this address must be known in your wallet. The address must\n"
            "                              be unused and must differ from the collateralAddress\n"
        },
    };

    auto it = mapParamHelp.find(strParamName);
    if (it == mapParamHelp.end())
        throw std::runtime_error(strprintf("FIXME: WRONG PARAM NAME %s!", strParamName));

    return strprintf(it->second, nParamNum);
}

// Allows to specify address or priv key. In case of address, the priv key is taken from the wallet
static CKey ParsePrivKey(CWallet* pwallet, const std::string &strKeyOrAddress, bool allowAddresses = true) {
    CBitcoinAddress address;
    if (allowAddresses && address.SetString(strKeyOrAddress) && address.IsValid()) {
        if (!pwallet) {
            throw std::runtime_error("addresses not supported when wallet is disabled");
        }
        EnsureWalletIsUnlocked(pwallet);
        CKeyID keyId;
        CKey key;
        if (!address.GetKeyID(keyId) || !pwallet->GetKey(keyId, key))
            throw std::runtime_error(strprintf("non-wallet or invalid address %s", strKeyOrAddress));
        return key;
    }

    CBitcoinSecret secret;
    if (!secret.SetString(strKeyOrAddress) || !secret.IsValid()) {
        throw std::runtime_error(strprintf("invalid priv-key/address %s", strKeyOrAddress));
    }
    return secret.GetKey();
}

static CKeyID ParsePubKeyIDFromAddress(const std::string& strAddress, const std::string& paramName)
{
    CBitcoinAddress address(strAddress);
    CKeyID keyID;
    if (!address.IsValid() || !address.GetKeyID(keyID)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a valid P2PKH address, not %s", paramName, strAddress));
    }
    return keyID;
}

static CBLSPublicKey ParseBLSPubKey(const std::string& hexKey, const std::string& paramName)
{
    CBLSPublicKey pubKey;
    if (!pubKey.SetHexStr(hexKey)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a valid BLS public key, not %s", paramName, hexKey));
    }
    return pubKey;
}

static CBLSSecretKey ParseBLSSecretKey(const std::string& hexKey, const std::string& paramName)
{
    CBLSSecretKey secKey;
    if (!secKey.SetHexStr(hexKey)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a valid BLS secret key", paramName));
    }
    return secKey;
}

template<typename SpecialTxPayload>
static void FundSpecialTx(CWallet* pwallet, CMutableTransaction& tx, const SpecialTxPayload& payload, const CTxDestination& destChange)
{
    assert(pwallet != NULL);
    LOCK2(cs_main, pwallet->cs_wallet);

    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION);
    ds << payload;
    tx.vExtraPayload.assign(ds.begin(), ds.end());

    static CTxOut dummyTxOut(0, CScript() << OP_RETURN);
    std::vector<CRecipient> vecSend;
    bool dummyTxOutAdded = false;

    if (tx.vout.empty()) {
        // add dummy txout as CreateTransaction requires at least one recipient
        tx.vout.emplace_back(dummyTxOut);
        dummyTxOutAdded = true;
    }

    for (const auto& txOut : tx.vout) {
        CRecipient recipient = {txOut.scriptPubKey, txOut.nValue, false};
        vecSend.push_back(recipient);
    }

    CCoinControl coinControl;
    coinControl.destChange = destChange;
    coinControl.fRequireAllInputs = false;

    std::vector<COutput> vecOutputs;
    pwallet->AvailableCoins(vecOutputs);

    for (const auto& out : vecOutputs) {
        CTxDestination txDest;
        if (ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, txDest)) {
            coinControl.Select(COutPoint(out.tx->tx->GetHash(), out.i));
        }
    }

    if (!coinControl.HasSelected()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No funds at specified address");
    }

    CWalletTx wtx;
    CReserveKey reservekey(pwallet);
    CAmount nFee;
    int nChangePos = -1;
    std::string strFailReason;

    if (!pwallet->CreateTransaction(vecSend, wtx, reservekey, nFee, nChangePos, strFailReason, &coinControl, false, tx.vExtraPayload.size())) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strFailReason);
    }

    tx.vin = wtx.tx->vin;
    tx.vout = wtx.tx->vout;

    if (dummyTxOutAdded && tx.vout.size() > 1) {
        // CreateTransaction added a change output, so we don't need the dummy txout anymore.
        // Removing it results in slight overpayment of fees, but we ignore this for now (as it's a very low amount).
        auto it = std::find(tx.vout.begin(), tx.vout.end(), dummyTxOut);
        assert(it != tx.vout.end());
        tx.vout.erase(it);
    }
}

template<typename SpecialTxPayload>
static void UpdateSpecialTxInputsHash(const CMutableTransaction& tx, SpecialTxPayload& payload)
{
    payload.inputsHash = CalcTxInputsHash(tx);
}

template<typename SpecialTxPayload>
static void SignSpecialTxPayloadByHash(const CMutableTransaction& tx, SpecialTxPayload& payload, const CKey& key)
{
    UpdateSpecialTxInputsHash(tx, payload);
    payload.vchSig.clear();

    uint256 hash = ::SerializeHash(payload);
    if (!CHashSigner::SignHash(hash, key, payload.vchSig)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "failed to sign special tx");
    }
}

template<typename SpecialTxPayload>
static void SignSpecialTxPayloadByString(const CMutableTransaction& tx, SpecialTxPayload& payload, const CKey& key)
{
    UpdateSpecialTxInputsHash(tx, payload);
    payload.vchSig.clear();

    std::string m = payload.MakeSignString();
    if (!CMessageSigner::SignMessage(m, payload.vchSig, key)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "failed to sign special tx");
    }
}

template<typename SpecialTxPayload>
static void SignSpecialTxPayloadByHash(const CMutableTransaction& tx, SpecialTxPayload& payload, const CBLSSecretKey& key)
{
    UpdateSpecialTxInputsHash(tx, payload);

    uint256 hash = ::SerializeHash(payload);
    payload.sig = key.Sign(hash);
}

static std::string SignAndSendSpecialTx(const CMutableTransaction& tx)
{
    LOCK(cs_main);

    CValidationState state;
    if (!CheckSpecialTx(tx, chainActive.Tip(), state)) {
        throw std::runtime_error(FormatStateMessage(state));
    }

    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION);
    ds << tx;

    JSONRPCRequest signRequest;
    signRequest.params.setArray();
    signRequest.params.push_back(HexStr(ds.begin(), ds.end()));
    UniValue signResult = signrawtransaction(signRequest);

    JSONRPCRequest sendRequest;
    sendRequest.params.setArray();
    sendRequest.params.push_back(signResult["hex"].get_str());
    return sendrawtransaction(sendRequest).get_str();
}

void protx_register_fund_help(CWallet* const pwallet)
{
    throw std::runtime_error(
            "protx register_fund \"collateralAddress\" \"ipAndPort\" \"ownerAddress\" \"operatorPubKey\"\n"
            "\nCreates, funds and sends a ProTx to the network. The resulting transaction will move BZX\n"
            "to the address specified by collateralAddress and will then function as the collateral of your\n"
            "masternode.\n"
            "A few of the limitations you see in the arguments are temporary and might be lifted after DIP3\n"
            "is fully deployed.\n"
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            + GetHelpString(1, "collateralAddress")
            + GetHelpString(2, "ipAndPort")
            + GetHelpString(3, "ownerAddress")
            + GetHelpString(4, "operatorPubKey") +
            "\nResult:\n"
            "\"txid\"                        (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("protx", "register_fund \"XrVhS9LogauRJGJu2sHuryjhpuex4RNPSb\" \"1.2.3.4:1234\" \"Xt9AMWaYSz7tR7Uo7gzXA3m4QmeWgrR3rr\" \"93746e8731c57f87f79b3620a7982924e2931717d49540a85864bd543de11c43fb868fd63e501a1db37e19ed59ae6db4\"")
    );
}

void protx_register_help(CWallet* const pwallet)
{
    throw std::runtime_error(
            "protx register \"collateralHash\" collateralIndex \"ipAndPort\" \"ownerAddress\" \"operatorPubKey\"\n"
            "\nSame as \"protx register_fund\", but with an externally referenced collateral.\n"
            "The collateral is specified through \"collateralHash\" and \"collateralIndex\" and must be an unspent\n"
            "transaction output spendable by this wallet. It must also not be used by any other masternode.\n"
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            + GetHelpString(1, "collateralHash")
            + GetHelpString(2, "collateralIndex")
            + GetHelpString(3, "ipAndPort")
            + GetHelpString(4, "ownerAddress")
            + GetHelpString(5, "operatorPubKey") +
            "\nResult:\n"
            "\"txid\"                        (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("protx", "register \"0123456701234567012345670123456701234567012345670123456701234567\" 0 \"1.2.3.4:1234\" \"Xt9AMWaYSz7tR7Uo7gzXA3m4QmeWgrR3rr\" \"93746e8731c57f87f79b3620a7982924e2931717d49540a85864bd543de11c43fb868fd63e501a1db37e19ed59ae6db4\"")
    );
}

UniValue protx_register(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    bool isExternalRegister = request.params[0].get_str() == "register";
    bool isFundRegister = request.params[0].get_str() == "register_fund";

    if (isFundRegister && (request.fHelp || (request.params.size() != 6 && request.params.size() != 7))) {
        protx_register_fund_help(pwallet);
    } else if (isExternalRegister && (request.fHelp || (request.params.size() != 7 && request.params.size() != 8))) {
        protx_register_help(pwallet);
    }

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (isExternalRegister || isFundRegister) {
        EnsureWalletIsUnlocked(pwallet);
    }

    size_t paramIdx = 1;

    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = TRANSACTION_PROVIDER_REGISTER;

    CProRegTx ptx;
    ptx.nVersion = CProRegTx::CURRENT_VERSION;

    if (isFundRegister) {
        CBitcoinAddress collateralAddress(request.params[paramIdx].get_str());
        if (!collateralAddress.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("invalid collaterall address: %s", request.params[paramIdx].get_str()));
        }
        CScript collateralScript = GetScriptForDestination(collateralAddress.Get());

        CTxOut collateralTxOut(collateralAmount, collateralScript);
        tx.vout.emplace_back(collateralTxOut);

        paramIdx++;
    } else {
        uint256 collateralHash = ParseHashV(request.params[paramIdx], "collateralHash");
        int32_t collateralIndex = ParseInt32V(request.params[paramIdx + 1], "collateralIndex");
        if (collateralHash.IsNull() || collateralIndex < 0) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("invalid hash or index: %s-%d", collateralHash.ToString(), collateralIndex));
        }

        ptx.collateralOutpoint = COutPoint(collateralHash, (uint32_t)collateralIndex);
        paramIdx += 2;

        // TODO unlock on failure
        LOCK(pwallet->cs_wallet);
        pwallet->LockCoin(ptx.collateralOutpoint);
    }

    if (request.params[paramIdx].get_str() != "") {
        if (!Lookup(request.params[paramIdx].get_str().c_str(), ptx.addr, Params().GetDefaultPort(), false)) {
            throw std::runtime_error(strprintf("invalid network address %s", request.params[paramIdx].get_str()));
        }
    }

    CKey keyOwner = ParsePrivKey(pwallet, request.params[paramIdx + 1].get_str(), true);
    CBLSPublicKey pubKeyOperator = ParseBLSPubKey(request.params[paramIdx + 2].get_str(), "operator BLS address");
    CKeyID keyIDVoting = keyOwner.GetPubKey().GetID();
    ptx.nOperatorReward = 0;

    CBitcoinAddress payoutAddress(request.params[paramIdx + 3].get_str());
    if (!payoutAddress.IsValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("invalid payout address: %s", request.params[paramIdx + 3].get_str()));
    }

    ptx.keyIDOwner = keyOwner.GetPubKey().GetID();
    ptx.pubKeyOperator = pubKeyOperator;
    ptx.keyIDVoting = keyIDVoting;
    ptx.scriptPayout = GetScriptForDestination(payoutAddress.Get());

    if (!isFundRegister) {
        // make sure fee calculation works
        ptx.vchSig.resize(65);
    }

    CBitcoinAddress fundAddress = payoutAddress;
    if (request.params.size() > paramIdx + 4) {
        fundAddress = CBitcoinAddress(request.params[paramIdx + 4].get_str());
        if (!fundAddress.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid address: ") + request.params[paramIdx + 4].get_str());
    }

    FundSpecialTx(pwallet, tx, ptx, fundAddress.Get());
    UpdateSpecialTxInputsHash(tx, ptx);

    if (isFundRegister) {
        uint32_t collateralIndex = (uint32_t) -1;
        for (uint32_t i = 0; i < tx.vout.size(); i++) {
            if (tx.vout[i].nValue == collateralAmount) {
                collateralIndex = i;
                break;
            }
        }
        assert(collateralIndex != (uint32_t) -1);
        ptx.collateralOutpoint.n = collateralIndex;

        SetTxPayload(tx, ptx);
        return SignAndSendSpecialTx(tx);
    } else {
        // referencing external collateral

        Coin coin;
        if (!GetUTXOCoin(ptx.collateralOutpoint, coin)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("collateral not found: %s", ptx.collateralOutpoint.ToStringShort()));
        }
        CTxDestination txDest;
        CKeyID keyID;
        if (!ExtractDestination(coin.out.scriptPubKey, txDest) || !CBitcoinAddress(txDest).GetKeyID(keyID)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("collateral type not supported: %s", ptx.collateralOutpoint.ToStringShort()));
        }
    }
}

void protx_list_help()
{
    throw std::runtime_error(
            "protx list (\"type\" \"detailed\" \"height\")\n"
            "\nLists all ProTxs in your wallet or on-chain, depending on the given type.\n"
            "If \"type\" is not specified, it defaults to \"registered\".\n"
            "If \"detailed\" is not specified, it defaults to \"false\" and only the hashes of the ProTx will be returned.\n"
            "If \"height\" is not specified, it defaults to the current chain-tip.\n"
            "\nAvailable types:\n"
            "  registered   - List all ProTx which are registered at the given chain height.\n"
            "                 This will also include ProTx which failed PoSe verfication.\n"
            "  valid        - List only ProTx which are active/valid at the given chain height.\n"
            "  wallet       - List only ProTx which are found in your wallet at the given chain height.\n"
            "                 This will also include ProTx which failed PoSe verfication.\n"
    );
}

static bool CheckWalletOwnsKey(CWallet* pwallet, const CKeyID& keyID) {
    if (!pwallet) {
        return false;
    }
    return pwallet->HaveKey(keyID);
}

static bool CheckWalletOwnsScript(CWallet* pwallet, const CScript& script) {
    if (!pwallet) {
        return false;
    }

    CTxDestination dest;
    if (ExtractDestination(script, dest)) {
        if ((boost::get<CKeyID>(&dest) && pwallet->HaveKey(*boost::get<CKeyID>(&dest))) || (boost::get<CScriptID>(&dest) && pwallet->HaveCScript(*boost::get<CScriptID>(&dest)))) {
            return true;
        }
    }
    return false;
}

UniValue BuildDMNListEntry(CWallet* pwallet, const CDeterministicMNCPtr& dmn, bool detailed)
{
    if (!detailed) {
        return dmn->proTxHash.ToString();
    }

    UniValue o(UniValue::VOBJ);

    dmn->ToJson(o);

    int confirmations = GetUTXOConfirmations(dmn->collateralOutpoint);
    o.push_back(Pair("confirmations", confirmations));

    bool hasOwnerKey = CheckWalletOwnsKey(pwallet, dmn->pdmnState->keyIDOwner);
    bool ownsCollateral = false;
    CTransactionRef collateralTx;
    uint256 tmpHashBlock;
    if (GetTransaction(dmn->collateralOutpoint.hash, collateralTx, Params().GetConsensus(), tmpHashBlock)) {
        ownsCollateral = CheckWalletOwnsScript(pwallet, collateralTx->vout[dmn->collateralOutpoint.n].scriptPubKey);
    }

    UniValue walletObj(UniValue::VOBJ);
    walletObj.push_back(Pair("hasOwnerKey", hasOwnerKey));
    walletObj.push_back(Pair("ownsCollateral", ownsCollateral));
    walletObj.push_back(Pair("ownsPayeeScript", CheckWalletOwnsScript(pwallet, dmn->pdmnState->scriptPayout)));
    o.push_back(Pair("wallet", walletObj));

    return o;
}

UniValue protx_list(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        protx_list_help();
    }

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    std::string type = "registered";
    if (request.params.size() > 1) {
        type = request.params[1].get_str();
    }

    UniValue ret(UniValue::VARR);

    LOCK(cs_main);

    if (type == "wallet") {
        if (!pwallet) {
            throw std::runtime_error("\"protx list wallet\" not supported when wallet is disabled");
        }
        LOCK2(cs_main, pwallet->cs_wallet);

        if (request.params.size() > 3) {
            protx_list_help();
        }

        bool detailed = request.params.size() > 2 ? ParseBoolV(request.params[2], "detailed") : false;

        int height = request.params.size() > 3 ? ParseInt32V(request.params[3], "height") : chainActive.Height();
        if (height < 1 || height > chainActive.Height()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid height specified");
        }

        std::vector<COutPoint> vOutpts;
        pwallet->ListProTxCoins(vOutpts);
        std::set<COutPoint> setOutpts;
        for (const auto& outpt : vOutpts) {
            setOutpts.emplace(outpt);
        }

        CDeterministicMNList mnList = deterministicMNManager->GetListForBlock(chainActive[height]);
        mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
            if (setOutpts.count(dmn->collateralOutpoint) ||
                CheckWalletOwnsKey(pwallet, dmn->pdmnState->keyIDOwner) ||
                CheckWalletOwnsKey(pwallet, dmn->pdmnState->keyIDVoting) ||
                CheckWalletOwnsScript(pwallet, dmn->pdmnState->scriptPayout) ||
                CheckWalletOwnsScript(pwallet, dmn->pdmnState->scriptOperatorPayout)) {
                ret.push_back(BuildDMNListEntry(pwallet, dmn, detailed));
            }
        });
    } else if (type == "valid" || type == "registered") {
        if (request.params.size() > 4) {
            protx_list_help();
        }

        LOCK(cs_main);

        bool detailed = request.params.size() > 2 ? ParseBoolV(request.params[2], "detailed") : false;

        int height = request.params.size() > 3 ? ParseInt32V(request.params[3], "height") : chainActive.Height();
        if (height < 1 || height > chainActive.Height()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid height specified");
        }

        CDeterministicMNList mnList = deterministicMNManager->GetListForBlock(chainActive[height]);
        bool onlyValid = type == "valid";
        mnList.ForEachMN(onlyValid, [&](const CDeterministicMNCPtr& dmn) {
            ret.push_back(BuildDMNListEntry(pwallet, dmn, detailed));
        });
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid type specified");
    }

    return ret;
}

void protx_info_help()
{
    throw std::runtime_error(
            "protx info \"proTxHash\"\n"
            "\nReturns detailed information about a deterministic masternode.\n"
            "\nArguments:\n"
            + GetHelpString(1, "proTxHash") +
            "\nResult:\n"
            "{                             (json object) Details about a specific deterministic masternode\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("protx", "info \"0123456701234567012345670123456701234567012345670123456701234567\"")
    );
}

UniValue protx_info(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        protx_info_help();
    }

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    uint256 proTxHash = ParseHashV(request.params[1], "proTxHash");
    auto mnList = deterministicMNManager->GetListAtChainTip();
    auto dmn = mnList.GetMN(proTxHash);
    if (!dmn) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s not found", proTxHash.ToString()));
    }
    return BuildDMNListEntry(pwallet, dmn, true);
}

void protx_diff_help()
{
    throw std::runtime_error(
            "protx diff \"baseBlock\" \"block\"\n"
            "\nCalculates a diff between two deterministic masternode lists. The result also contains proof data.\n"
            "\nArguments:\n"
            "1. \"baseBlock\"           (numeric, required) The starting block height.\n"
            "2. \"block\"               (numeric, required) The ending block height.\n"
    );
}

static uint256 ParseBlock(const UniValue& v, std::string strName)
{
    AssertLockHeld(cs_main);

    try {
        return ParseHashV(v, strName);
    } catch (...) {
        int h = ParseInt32V(v, strName);
        if (h < 1 || h > chainActive.Height())
            throw std::runtime_error(strprintf("%s must be a block hash or chain height and not %s", strName, v.getValStr()));
        return *chainActive[h]->phashBlock;
    }
}

UniValue protx_diff(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3) {
        protx_diff_help();
    }

    LOCK(cs_main);
    uint256 baseBlockHash = ParseBlock(request.params[1], "baseBlock");
    uint256 blockHash = ParseBlock(request.params[2], "block");

    CSimplifiedMNListDiff mnListDiff;
    std::string strError;
    if (!BuildSimplifiedMNListDiff(baseBlockHash, blockHash, mnListDiff, strError)) {
        throw std::runtime_error(strError);
    }

    UniValue ret;
    mnListDiff.ToJson(ret);
    return ret;
}

[[ noreturn ]] void protx_help()
{
    throw std::runtime_error(
            "protx \"command\" ...\n"
            "Set of commands to execute ProTx related actions.\n"
            "To get help on individual commands, use \"help protx command\".\n"
            "\nArguments:\n"
            "1. \"command\"        (string, required) The command to execute\n"
            "\nAvailable commands:\n"
            "  register          - Create and send ProTx to network\n"
            "  register_fund     - Fund, create and send ProTx to network\n"
            "  list              - List ProTxs\n"
            "  info              - Return information about a ProTx\n"
            "  diff              - Calculate a diff and a proof between two masternode lists\n"
    );
}

UniValue protx(const JSONRPCRequest& request)
{
    if (request.fHelp && request.params.empty()) {
        protx_help();
    }

    std::string command;
    if (request.params.size() >= 1) {
        command = request.params[0].get_str();
    }
    if (command == "register" || command == "register_fund") {
        return protx_register(request);
    } else
    if (command == "list") {
        return protx_list(request);
    } else if (command == "info") {
        return protx_info(request);
    } else if (command == "diff") {
        return protx_diff(request);
    } else {
        protx_help();
    }
}

void bls_generate_help()
{
    throw std::runtime_error(
            "bls generate\n"
            "\nReturns a BLS secret/public key pair.\n"
            "\nResult:\n"
            "{\n"
            "  \"secret\": \"xxxx\",        (string) BLS secret key\n"
            "  \"public\": \"xxxx\",        (string) BLS public key\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("bls generate", "")
    );
}

UniValue bls_generate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        bls_generate_help();
    }

    CBLSSecretKey sk;
    sk.MakeNewKey();

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("secret", sk.ToString()));
    ret.push_back(Pair("public", sk.GetPublicKey().ToString()));
    return ret;
}

void bls_fromsecret_help()
{
    throw std::runtime_error(
            "bls fromsecret \"secret\"\n"
            "\nParses a BLS secret key and returns the secret/public key pair.\n"
            "\nArguments:\n"
            "1. \"secret\"                (string, required) The BLS secret key\n"
            "\nResult:\n"
            "{\n"
            "  \"secret\": \"xxxx\",        (string) BLS secret key\n"
            "  \"public\": \"xxxx\",        (string) BLS public key\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("bls fromsecret", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    );
}

UniValue bls_fromsecret(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        bls_fromsecret_help();
    }

    CBLSSecretKey sk;
    if (!sk.SetHexStr(request.params[1].get_str())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Secret key must be a valid hex string of length %d", sk.SerSize*2));
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("secret", sk.ToString()));
    ret.push_back(Pair("public", sk.GetPublicKey().ToString()));
    return ret;
}

[[ noreturn ]] void bls_help()
{
    throw std::runtime_error(
            "bls \"command\" ...\n"
            "Set of commands to execute BLS related actions.\n"
            "To get help on individual commands, use \"help bls command\".\n"
            "\nArguments:\n"
            "1. \"command\"        (string, required) The command to execute\n"
            "\nAvailable commands:\n"
            "  generate          - Create a BLS secret/public key pair\n"
            "  fromsecret        - Parse a BLS secret key and return the secret/public key pair\n"
            );
}

UniValue _bls(const JSONRPCRequest& request)
{
    if (request.fHelp && request.params.empty()) {
        bls_help();
    }

    std::string command;
    if (request.params.size() >= 1) {
        command = request.params[0].get_str();
    }

    if (command == "generate") {
        return bls_generate(request);
    } else if (command == "fromsecret") {
        return bls_fromsecret(request);
    } else {
        bls_help();
    }
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "evo",                "bls",                    &_bls,                   false, {}  },
    { "evo",                "protx",                  &protx,                  false, {}  },
};

void RegisterEvoRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++) {
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}
