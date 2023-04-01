## About the project 
Send bitcoin transactions using golang


## Usage
It's not recommended to use in production (or very carefully and advised beforehand with author)

Right now it's only possible to form transaction to send btc to P2SH address type

### Example

```go
privKey := "----YOUR_PRIVATE_KEY__N4Fwmvbictryk69BA5f---"
recepientAddress := "2N6SjJNhBgHqvgLZ8Wxc7Yi6jBSGjT9HNPL"

wifPrivateKey, err := btcutil.DecodeWIF(privKey)
if err != nil {
    require.NoError(t, err)
}

pkScriptDecoded, err := hex.DecodeString(your_pubkey_script_of_previous_txout)
if err != nil {
    require.NoError(t, err)
}

forgeIns := []ForgeTxIn{
    {
        Utxo: UTXO{
            TxID:         your_prev_transaction_id,
            Vout:         0,
            Value:        amount_of_txout,
            PubKeyScript: pkScriptDecoded,
        },
        WIFPrivKey: wifPrivateKey,
    },
}
forgeOuts := []ForgeTxOut{
    {
        Value:   your_amount_of_satoshi_to_spend, // decreased from first met output
        Address: recepientAddress,
    },
}
// this redeemTx you will propagate through electron/btc-node
// after serializing redeemTx.Serialize(buffer)
redeemTx, sumResult, err := ForgeTx(forgeIns, forgeOuts, tc.netParams)
```

## Roadmap
- Make all the features as in https://github.com/libitx/txforge
- Add handling of all possibles addresses
- Add possibility to send/inject scripts, not only spend a money


## Acknowledgements

- https://github.com/libitx/txforge - Inspiration for this library
- https://github.com/btcsuite/btcd - functionality of this library 
 