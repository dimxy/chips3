# test dice
import os
import time
import json
import subprocess
import random
from subprocess import check_output as go


def run_dice() :

# dicefund 031f89c2f89f298300afb3952675f9a024e7302252ef43b6fa4d5d66316f5864e1 0243692eb833239fde48b00fc3d7d62f89afeb7e435ce41a3271adb3460ef85c20 6d92705c876fc10034f1abba70ffac294df040d288ac82534675ec86b0fab62a 1
# dicebet 0243692eb833239fde48b00fc3d7d62f89afeb7e435ce41a3271adb3460ef85c20 031f89c2f89f298300afb3952675f9a024e7302252ef43b6fa4d5d66316f5864e1 af9ed0f9aad3254ab7ea3ff20c4382556447c0d25008b978f023730190839166 1 1:1
# diceclaim b 0243692eb833239fde48b00fc3d7d62f89afeb7e435ce41a3271adb3460ef85c20 01e38b2f79f28fc748de4852edbe8c566c46c9056436be9011066148ec4b6206 00266c0463a23f349372f8932c0fa8e3ee6287551ce55e9dde80fd1ed653079b c5eb48939e860ee7a0e71df192be7e7f675ae587a4b4ba999df086d60d56191c:1 a43483299d9038ba86bb8610d012e0a63afe6be67b8de314941a2c0245ddcc07:0

    random.seed()

    basecmd = "../src/chips-cli" 

    house_pk = "03d97fcb5ea80289df537ee84714a9e04ae4dae2bf24e7bf1bebdcbb76ed919867"
    # house_priv = "cSctaA8JBCZYmSjDjD7pdbdesuERZUWb7Lsr9BLUPtSazALtyMAu" -  must be in the wallet
    bettor_pk =  "0281a58d8925ae76e5df6cc374f7130b62e2df3ae3cee3f18edd9a0ca262902610" 
    # bettor_priv = "cSK2yZAnhZKnXWkaSk9rbKGtjwEA9yxLLu7zRQziZJHVKfFc3iE9" -  must be in the wallet

    # make entropies:
    house_ent = hex(random.randint(1, 0x7fffffff))[2:].zfill(64)
    bettor_ent = hex(random.randint(1, 0x7fffffff))[2:].zfill(64)    
    print("house_ent=", house_ent)
    print("bettor_ent=", bettor_ent)

    # make entropy hashes:
    output = go([basecmd, "-testnet", "dicehentropy", house_ent])
    house_hash = output.decode("utf-8").strip()
    output = go([basecmd, "-testnet", "dicehentropy", bettor_ent])
    bettor_hash = output.decode("utf-8").strip()
    print("house_hash=", house_hash)
    print("bettor_hash=", bettor_hash)

    # bettor amount and odds:
    bettor_amount = "0.2"
    odds = "50:50"

    print("creating bet proposal by bettor, amount:", bettor_amount, "odds:", odds, "...")
    output = go([basecmd, "-testnet", "dicecreatebettxproposal", bettor_pk, house_pk, bettor_amount, odds, bettor_hash])
    bettx = output.decode("utf-8").strip()
    assert(bettx.find("error") < 0)
    print("dicecreatebettxproposal created")

    print("accepting bet proposal by house...")
    output = go([basecmd, "-testnet", "diceacceptbettxproposal", house_pk, bettx, house_hash])
    bettxaccepted = output.decode("utf-8").strip()
    assert(bettxaccepted.find("error") < 0)
    print("diceacceptbettxproposal created and signed by house")

    print("signing bet proposal by bettor...")
    output = go([basecmd, "-testnet", "signrawtransactionwithwallet", bettxaccepted])
    outputdecoded = output.decode("utf-8").strip()
    bettxsigned = json.loads(outputdecoded)
    print("bettx signed with both bettor and house=", bettxsigned)
    assert(bettxsigned["complete"])

    output = go([basecmd, "-testnet", "sendrawtransaction", bettxsigned['hex']])
    bettxid = output.decode("utf-8").strip()
    assert(bettxid.find("error") < 0) # no error found

    # go([basecmd, "-testnet", "generate", "1", "100000000"])  

    # find vout with funds
    output = go([basecmd, "-testnet", "getrawtransaction", bettxid, "true"])
    strjson = output.decode("utf-8").strip()
    txjson = json.loads(strjson)
    txbettor_vout = -1
    txhouse_vout = -1

    for i in range(len(txjson['vout'])) :
        if txjson['vout'][i]['scriptPubKey']['type'] == 'multisig_with_txrule' :
            if txbettor_vout < 0 :
                txbettor_vout = i
            elif txhouse_vout < 0 :
                txhouse_vout = i

    print("debug: found txbettor_vout=", txbettor_vout, "txhouse_vout=", txhouse_vout)

    try :
        print("")
        print("trying to claim as house...")
        # try to claim as house
        output = go([basecmd, "-testnet", "diceclaim2", house_pk, house_ent, bettor_ent, bettxid + ":" + str(txhouse_vout), bettxid + ":" + str(txbettor_vout)])
        claimres = output.decode("utf-8").strip()
        print("diceclaim2 as house result:", claimres)
        if len(claimres) == 64 :   # returned non error but txid
            # go([basecmd, "-testnet", "generate", "1", "100000000"])  
            output = go([basecmd, "-testnet", "getrawtransaction", claimres, "true"])
            strjson = output.decode("utf-8").strip()
            txjson = json.loads(strjson)
            print("claimed from house (-txfee):", txjson['vout'][0]['value'], ", claimed from bettor:", txjson['vout'][1]['value'])

    except Exception as e :
        print("diceclaim2 as house error:", e)

    try :
        print("")
        print("trying to claim as bettor...")
        # as bettor
        output = go([basecmd, "-testnet", "diceclaim2", bettor_pk, house_ent, bettor_ent, bettxid + ":" + str(txhouse_vout), bettxid + ":" + str(txbettor_vout)])
        claimres = output.decode("utf-8").strip()
        print("diceclaim2 as bettor result:", claimres)
        if len(claimres) == 64 :   # returned non error but txid
            # go([basecmd, "-testnet", "generate", "1", "100000000"])  
            output = go([basecmd, "-testnet", "getrawtransaction", claimres, "true"])
            strjson = output.decode("utf-8").strip()
            txjson = json.loads(strjson)
            print("claimed from house (-txfee):", txjson['vout'][0]['value'], ", claimed from bettor:", txjson['vout'][1]['value'])

    except Exception as e :
        print("diceclaim2 as bettor error:", e)         
    
    # generate a block with the txns
    go([basecmd, "-testnet", "generate", "1", "100000000"])  

def main():
    run_dice()

if __name__ == "__main__":
    print("starting dice test")
    time.sleep(1)   
    main()