package tx_forge

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/pkg/errors"
)

//// You'll need UTXOs to fund a transaction. Use the `toUTXO` helper to turn
//// your UTXO data into the required objects.
//const utxo = toUTXO({
//txid: "db2b17b3f9fd3085f1941dcc0621d3791e4b3c221bbf11d38a334b9aee4f38c4",       // utxo transaction id
//vout: 0,       // utxo output index
//satoshis: 49832,   // utxo amount
//script: "a91490c6addad6abcb929b6edd2833397aed1b5c6f5e87"       // utxo lock script
//})
//
//// Forge a transaction
//const tx = forgeTx({
//inputs: [
//P2PKH.unlock(utxo, { privkey: "cMdRNN4Fwmvbictryk69BA5fDGxHqFe7iNDxCC3H9yhxCWoKvUML" })
//],
//outputs: [
//P2PKH.lock(49664, { address: '2N6SjJNhBgHqvgLZ8Wxc7Yi6jBSGjT9HNPL' }),
//],
//change: { address: '2N6SjJNhBgHqvgLZ8Wxc7Yi6jBSGjT9HNPL' }
//})

// TxIn: P2SH-P2WPKH, P2SH, P2PKH, P2PK
// 	 	 in the future: P2WSH, P2WPKH

// TxOut: <ConvertibleTo interface>
//

type ForgeTxInSize struct {
	Witness        int
	SerializedSize int
}

type UTXO struct {
	TxID         string `json:"txid"`
	Vout         uint32 `json:"vout"`         // vout index
	Value        int    `json:"value"`        // in satoshis
	PubKeyScript []byte `json:"pubKeyScript"` // decoded from hex
}

type ForgeTxIn struct {
	Utxo       UTXO         `json:"utxo"`
	WIFPrivKey *btcutil.WIF `json:"wifPrivKey"`
}

type ForgeTxOut struct {
	Value   int    `json:"value"`
	Address string `json:"address"`
}

// DefaultFeeRate is minimal reasonable fee rate
var DefaultFeeRate = 2

type Params struct {
	FeeRate    int
	Network    *chaincfg.Params
	NeedToSign bool
}

// ForgeTx is facade to forgeTx with fee calculation
func ForgeTx(txins []ForgeTxIn, txouts []ForgeTxOut, params *Params) (*wire.MsgTx, *ForgeSummary, error) {
	redeemTx, _, err := forgeTx(txins, txouts, params)
	if err != nil {
		return nil, nil, err
	}

	sizeWithWitness := redeemTx.SerializeSize()
	sizeWithoutWitness := redeemTx.SerializeSizeStripped()

	vSize := (sizeWithoutWitness*3 + sizeWithWitness) / 4
	calculatedFee := vSize * params.FeeRate

	txOutsWithFee := make([]ForgeTxOut, 0, len(txouts))

	// TODO: reverse slice to cut fee from last output, then re-reverse to put a cut output in the end,
	// 		 now we are handling only case with one output
	for _, out := range txouts {
		txOutValue := out.Value - calculatedFee

		// transaction output is gone to the fee
		if txOutValue < 0 {
			calculatedFee = calculatedFee - out.Value
			continue
		}
		calculatedFee = 0

		txOutsWithFee = append(txOutsWithFee, ForgeTxOut{
			Value:   txOutValue,
			Address: out.Address,
		})
	}

	if len(txOutsWithFee) == 0 {
		return nil, nil, errors.New("fee is greater than all txouts")
	}

	return forgeTx(txins, txOutsWithFee, params)
}

type ForgeSummary struct {
	Fee         int
	TotalInput  int
	TotalOutput int
}

// forgeTx just creates and signs transaction, without fee calculating, what you put - that you get
// fee, totalInput, totalOutput
func forgeTx(txins []ForgeTxIn, txouts []ForgeTxOut, params *Params) (*wire.MsgTx, *ForgeSummary, error) {
	if len(txins) == 0 || len(txouts) == 0 {
		return nil, nil, errors.Errorf("has not enough txins or txouts: %d, %d", len(txins), len(txouts))
	}

	if params.FeeRate < 1 {
		return nil, nil, errors.Errorf("invalid FeeRate: %d", params.FeeRate)
	}
	if params.Network == nil {
		return nil, nil, errors.Errorf("params.Network can't be nil")
	}

	var inputsSum int
	redeemTx := wire.NewMsgTx(wire.TxVersion)
	outPointsMap := make(map[wire.OutPoint]*wire.TxOut, len(txins))
	var outputFetcher prevOutputFetcher = func(out wire.OutPoint) *wire.TxOut {
		return outPointsMap[out]
	}

	for _, txin := range txins {
		inputsSum += txin.Utxo.Value
		redeemTxIn, err := createTxIn(&txin, outPointsMap, params)

		if err != nil {
			return nil, nil, err
		}

		redeemTx.AddTxIn(redeemTxIn)
		// TODO: add txIn size to txInSum
	}

	// output validation
	var outputsSum int
	for _, txout := range txouts {
		destinationAddr, err := btcutil.DecodeAddress(txout.Address, params.Network)
		if err != nil {
			return nil, nil, err
		}

		// locking script
		destinationAddrByte, err := txscript.PayToAddrScript(destinationAddr)
		if err != nil {
			return nil, nil, err
		}

		outputsSum += txout.Value
		redeemTxOut := wire.NewTxOut(int64(txout.Value), destinationAddrByte)

		redeemTx.AddTxOut(redeemTxOut)
	}

	if outputsSum > inputsSum {
		return nil, nil, errors.Errorf("outputsSum > inputsSum: %d > %d", outputsSum, inputsSum)
	}

	if params.NeedToSign {
		for i, txin := range redeemTx.TxIn {
			sigHashes := txscript.NewTxSigHashes(redeemTx, outputFetcher)

			witnessSignature, err := txscript.WitnessSignature(redeemTx, sigHashes, i, int64(txins[i].Utxo.Value), txin.SignatureScript[1:], txscript.SigHashAll, txins[i].WIFPrivKey.PrivKey, true)
			if err != nil {
				return nil, nil, err
			}
			txin.Witness = witnessSignature

			// checking signature by executing lock+unlock script
			vm, err := txscript.NewEngine(txins[i].Utxo.PubKeyScript, redeemTx, i, txscript.StandardVerifyFlags, nil, sigHashes, int64(txins[i].Utxo.Value), outputFetcher)
			if err != nil {
				return nil, nil, err
			}

			err = vm.Execute()
			if err != nil {
				return nil, nil, err
			}
		}
	}

	return redeemTx,
		&ForgeSummary{
			Fee:         inputsSum - outputsSum,
			TotalInput:  inputsSum,
			TotalOutput: outputsSum,
		},
		nil
}

func createTxIn(txin *ForgeTxIn, outPointsMap map[wire.OutPoint]*wire.TxOut, params *Params) (*wire.TxIn, error) {
	// out point
	utxoHash, err := chainhash.NewHashFromStr(txin.Utxo.TxID)
	if err != nil {
		return nil, errors.Wrapf(err, "txId: %s", txin.Utxo.TxID)
	}

	outPoint := wire.NewOutPoint(utxoHash, txin.Utxo.Vout)
	outPointsMap[*outPoint] = &wire.TxOut{
		Value:    int64(txin.Utxo.Value),
		PkScript: txin.Utxo.PubKeyScript,
	}

	var witnessProgram []byte

	if params.NeedToSign {
		// redeem script
		addrPubKey, err := btcutil.NewAddressPubKey(txin.WIFPrivKey.PrivKey.PubKey().SerializeCompressed(), params.Network)
		if err != nil {
			return nil, err
		}

		p2kh, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(addrPubKey.ScriptAddress()), params.Network)
		if err != nil {
			return nil, err
		}

		p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(p2kh.ScriptAddress(), params.Network)
		if err != nil {
			return nil, err
		}

		witnessProgram, err = txscript.PayToAddrScript(p2wkhAddr) // it's redeem script for scriptSig
		if err != nil {
			return nil, err
		}
	} else {
		// just to fill witness script with something
		witnessProgram = []byte{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10}
	}

	resultTxIn := wire.NewTxIn(outPoint, append([]byte{22}, witnessProgram...), nil)

	return resultTxIn, nil
}

type prevOutputFetcher func(out wire.OutPoint) *wire.TxOut

func (s prevOutputFetcher) FetchPrevOutput(out wire.OutPoint) *wire.TxOut {
	return s(out)
}

// GetWitnessProgramFromPrivateKey returns witness program, or redeem script. It can be HASH160 to become to what in pkScript
func GetWitnessProgramFromPrivateKey(wifPrivateKey *btcutil.WIF, networkParams *chaincfg.Params) ([]byte, error) {
	addrPubKey, err := btcutil.NewAddressPubKey(wifPrivateKey.PrivKey.PubKey().SerializeCompressed(), networkParams)
	if err != nil {
		return nil, err
	}

	p2kh, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(addrPubKey.ScriptAddress()), networkParams)
	if err != nil {
		return nil, err
	}

	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(p2kh.ScriptAddress(), networkParams)
	if err != nil {
		return nil, err
	}

	return txscript.PayToAddrScript(p2wkhAddr) // it's redeem script for scriptSig
}

// GetPkScriptFromWitnessProgram gets p2sh pkScript from 22 byte witness program
func GetPkScriptFromWitnessProgram(witnessProgram []byte) []byte {
	pkScript2 := append([]byte{txscript.OP_HASH160, txscript.OP_DATA_20}, btcutil.Hash160(witnessProgram)...)
	return append(pkScript2, txscript.OP_EQUAL)
}
