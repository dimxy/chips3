# test 
import os
import time
import json
import subprocess
from subprocess import check_output as go


def run_dice() :

# dicefund 039c8a1e9a2f497970651bfd5c57aa9d7e358c46e0efa04e009d5c6d83e95c7bdd 02e2f2cacf0bfe63903b48b13c58bc5972b01317c7aeae2de54cc61dd5c72707b9 6d92705c876fc10034f1abba70ffac294df040d288ac82534675ec86b0fab62a 1
# dicebet 02e2f2cacf0bfe63903b48b13c58bc5972b01317c7aeae2de54cc61dd5c72707b9 039c8a1e9a2f497970651bfd5c57aa9d7e358c46e0efa04e009d5c6d83e95c7bdd af9ed0f9aad3254ab7ea3ff20c4382556447c0d25008b978f023730190839166 1 1:1
# diceclaim b 02e2f2cacf0bfe63903b48b13c58bc5972b01317c7aeae2de54cc61dd5c72707b9 01e38b2f79f28fc748de4852edbe8c566c46c9056436be9011066148ec4b6206 00266c0463a23f349372f8932c0fa8e3ee6287551ce55e9dde80fd1ed653079b c5eb48939e860ee7a0e71df192be7e7f675ae587a4b4ba999df086d60d56191c:1 a43483299d9038ba86bb8610d012e0a63afe6be67b8de314941a2c0245ddcc07:0

    house_pk = "039c8a1e9a2f497970651bfd5c57aa9d7e358c46e0efa04e009d5c6d83e95c7bdd"
    bettor_pk = "02e2f2cacf0bfe63903b48b13c58bc5972b01317c7aeae2de54cc61dd5c72707b9"
    house_ent = "01e38b2f79f28fc748de4852edbe8c566c46c9056436be9011066148ec4b6206"
    bettor_ent = "00266c0463a23f349372f8932c0fa8e3ee6287551ce55e9dde80fd1ed653079b"
    house_hash = "6d92705c876fc10034f1abba70ffac294df040d288ac82534675ec86b0fab62a"
    bettor_hash = "af9ed0f9aad3254ab7ea3ff20c4382556447c0d25008b978f023730190839166"
    house_amount = "2"
    bettor_amount = "2"
    odds = "100:1"

    basecmd = "/Users/dimxy/repo/chips3/src/chips-cli" 

    print("funding house, amount:", house_amount)
    output = go([basecmd, "-regtest", "dicefund", house_pk, bettor_pk, house_hash, house_amount])
    txidhouse = output.decode("utf-8").strip()
    print("dicefund txid=", txidhouse)

    print("making bet, amount:", bettor_amount, "odds:", odds)
    output = go([basecmd, "-regtest", "dicebet", bettor_pk, house_pk, bettor_hash, bettor_amount, odds])
    txidbettor = output.decode("utf-8").strip()
    print("dicebet txid=", txidbettor)

    go([basecmd, "-regtest", "generate", "2"])  

    # find vout with funds
    output = go([basecmd, "-regtest", "getrawtransaction", txidhouse, "true"])
    strjson = output.decode("utf-8").strip()
    txjson = json.loads(strjson)
    txhouse_vout = 0
    if txjson['vout'][0]['scriptPubKey']['type'] != 'multisig_with_txrule' :
        txhouse_vout = 1
    # print("txhouse_vout=", txhouse_vout)

    output = go([basecmd, "-regtest", "getrawtransaction", txidbettor, "true"])
    strjson = output.decode("utf-8").strip()
    txjson = json.loads(strjson)
    txbettor_vout = 0
    if txjson['vout'][0]['scriptPubKey']['type'] != 'multisig_with_txrule' :
        txbettor_vout = 1
    # print("txbettor_vout=", txbettor_vout)


    try :
        print("")
        print("trying to claim as house...")
        # try to claim as house
        output = go([basecmd, "-regtest", "diceclaim", 'h', house_pk, house_ent, bettor_ent, txidhouse + ":" + str(txhouse_vout), txidbettor + ":" + str(txbettor_vout)])
        claimres = output.decode("utf-8").strip()
        print("diceclaim as house result:", claimres)
        if len(claimres) == 64 :   # returned non error but txid
            go([basecmd, "-regtest", "generate", "1"])  
            output = go([basecmd, "-regtest", "getrawtransaction", claimres, "true"])
            strjson = output.decode("utf-8").strip()
            txjson = json.loads(strjson)
            print("claimed from house:", txjson['vout'][0]['value'], "claimed from bettor:", txjson['vout'][1]['value'])

    except Exception as e :
        print("diceclaim as house error:", e)

    try :
        print("")
        print("trying to claim as bettor...")
        # as bettor
        output = go([basecmd, "-regtest", "diceclaim", 'b', bettor_pk, house_ent, bettor_ent, txidhouse + ":" + str(txhouse_vout), txidbettor + ":" + str(txbettor_vout)])
        claimres = output.decode("utf-8").strip()
        print("diceclaim as bettor result:", claimres)
        if len(claimres) == 64 :   # returned non error but txid
            go([basecmd, "-regtest", "generate", "1"])  
            output = go([basecmd, "-regtest", "getrawtransaction", claimres, "true"])
            strjson = output.decode("utf-8").strip()
            txjson = json.loads(strjson)
            print("claimed from bettor:", txjson['vout'][0]['value'], "claimed from house:", txjson['vout'][1]['value'])

    except Exception as e :
        print("diceclaim as bettor error:", e)         



def main():
    run_dice()

if __name__ == "__main__":
    print("starting dice test")
    time.sleep(1)   
    main()