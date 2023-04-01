package tx_forge

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestForgeTx(t *testing.T) {
	testParams := &Params{
		FeeRate: DefaultFeeRate,
		Network: &chaincfg.TestNet3Params,
	}
	privKey1 := "cMdRNN4Fwmvbictryk69BA5fDGxHqFe7iNDxCC3H9yhxCWoKvUML"
	p2sh1 := "2N6SjJNhBgHqvgLZ8Wxc7Yi6jBSGjT9HNPL"

	pkScript1 := "a91490c6addad6abcb929b6edd2833397aed1b5c6f5e87"
	prevTxId1 := "0bd2fd0e9b5629105884fc4c42f77ae48a6a4fb649df6f678cc6bac28e39e2ad"

	privKey2 := "cNsAQ7t1SFFDvXsLaMZ4xTg9bqK9RZNWnQDHmPGEPpn5QVRgGGXV"
	//p2sh2 := "2MypVYXNoecDgiQNBr8LhJXseDAx9wn9Zrq"
	prevTxId2 := "0bd2fd0e9b5629105884fc4c42f76ae48a6a4fb649df6f678cc6bac28e39e2ad"

	privKey3 := "cVUJncM2GPMBnb3TFS8zU4CQ1qHgZLRdEwg3iFyZwds3AL3EK56U"
	//p2sh3 := "2N1qk9szETpDxTqcANa3mvcQKtbT4ihyg7C"
	prevTxId3 := "0bd2fd0e9b5629105884fc4c42f75ae48a6a4fb649df6f678cc6bac28e39e2ad"

	privKey4 := "cTrswWxoZEqaPwMizFtnezNk8nKwHaQqC4i6LTeHumQTackhk8Bz"
	//p2sh4 := "2NAY8kMmdZh7qpN4jsqjT3Yr8oQv65RbXB3"
	prevTxId4 := "0bd2fd0e9b5629105884fc4c42f74ae48a6a4fb649df6f678cc6bac28e39e2ad"

	privKey5 := "cUmudPVY1D5vevqQLkmToJxXWVzgZLW2prpts9DnSsHpqnkFq4kp"
	//p2sh5 := "2NEQ4oQr6K9Ch4n8hXGvsiqwZjzCpaLpfqh"
	prevTxId5 := "0bd2fd0e9b5629105884fc4c42f73ae48a6a4fb649df6f678cc6bac28e39e2ad"

	t.Run("ForgeTx 1 to 1", func(t *testing.T) {
		wifPrivateKey, err := btcutil.DecodeWIF(privKey1)
		require.NoError(t, err)

		witnessProgram, err := GetWitnessProgramFromPrivateKey(wifPrivateKey, testParams.Network)
		require.NoError(t, err)

		p2shAddress, err := btcutil.DecodeAddress(p2sh1, testParams.Network)
		require.NoError(t, err)

		wantPkScript, err := txscript.PayToAddrScript(p2shAddress)
		require.NoError(t, err)

		wifPrivateKeyOfDestination, err := btcutil.DecodeWIF(privKey1)
		require.NoError(t, err)
		witnessProgramFromPrivateKey, err := GetWitnessProgramFromPrivateKey(wifPrivateKeyOfDestination, testParams.Network)
		require.NoError(t, err)
		pkScriptFromPrivKey := GetPkScriptFromWitnessProgram(witnessProgramFromPrivateKey)

		wantSigScript := append([]byte{22}, witnessProgram...)

		testCases := []struct {
			name        string
			privKey     string
			destination string
			prevTxID    string
			pkScript    string
			balance     int
			output      int
			netParams   *Params

			wantAmount              int
			wantFeeAmount           int
			wantWitnessSignatureLen int
			wantErr                 bool // TODO: refactor to check specific errors
		}{
			{
				name:                    "ok",
				privKey:                 privKey1,
				destination:             p2sh1,
				prevTxID:                prevTxId1,
				pkScript:                pkScript1,
				balance:                 49664,
				output:                  49664,
				netParams:               testParams,
				wantAmount:              49398,
				wantFeeAmount:           266,
				wantErr:                 false,
				wantWitnessSignatureLen: 72,
			},
			{
				name:                    "ok low balance",
				privKey:                 privKey1,
				destination:             p2sh1,
				prevTxID:                prevTxId1,
				pkScript:                pkScript1,
				balance:                 1000,
				output:                  1000,
				netParams:               testParams,
				wantAmount:              1000 - 266,
				wantFeeAmount:           266,
				wantErr:                 false,
				wantWitnessSignatureLen: 71,
			},
			{
				name:                    "ok high balance",
				privKey:                 privKey1,
				destination:             p2sh1,
				prevTxID:                prevTxId1,
				pkScript:                pkScript1,
				balance:                 100_000_000,
				output:                  100_000_000,
				netParams:               testParams,
				wantAmount:              100_000_000 - 266,
				wantFeeAmount:           266,
				wantErr:                 false,
				wantWitnessSignatureLen: 72,
			},
			{
				name:        "error insufficient balance",
				privKey:     privKey1,
				destination: p2sh1,
				prevTxID:    prevTxId1,
				pkScript:    pkScript1,
				balance:     200,
				output:      200,
				netParams:   testParams,
				wantErr:     true,
			},
			{
				name:          "error private key can't unlock the script",
				privKey:       privKey2,
				destination:   p2sh1,
				prevTxID:      prevTxId1,
				pkScript:      pkScript1,
				balance:       49664,
				output:        49664,
				netParams:     testParams,
				wantAmount:    49398,
				wantFeeAmount: 266,
				wantErr:       true,
			},
			{
				name:        "error, wrong network",
				privKey:     privKey1,
				destination: p2sh1,
				prevTxID:    prevTxId1,
				pkScript:    pkScript1,
				balance:     49664,
				output:      49664,
				netParams: &Params{
					FeeRate: DefaultFeeRate,
					Network: &chaincfg.MainNetParams,
				},
				wantAmount:              49398,
				wantFeeAmount:           266,
				wantErr:                 true,
				wantWitnessSignatureLen: 72,
			},
			{
				name:                    "error, destination address is for wrong network",
				privKey:                 privKey1,
				destination:             "3CuDaAXPUQJGLpyaZThy12s4APdd2qXK1k",
				prevTxID:                prevTxId1,
				pkScript:                pkScript1,
				balance:                 49664,
				output:                  50000,
				netParams:               testParams,
				wantAmount:              49398,
				wantFeeAmount:           266,
				wantErr:                 true,
				wantWitnessSignatureLen: 72,
			},
			{
				name:        "error, fee rate is 0",
				privKey:     privKey1,
				destination: "3CuDaAXPUQJGLpyaZThy12s4APdd2qXK1k",
				prevTxID:    prevTxId1,
				pkScript:    pkScript1,
				balance:     49664,
				output:      50000,
				netParams: &Params{
					FeeRate: 0,
					Network: testParams.Network,
				},
				wantAmount:              49398,
				wantFeeAmount:           266,
				wantErr:                 true,
				wantWitnessSignatureLen: 72,
			},
			{
				name:        "error, network is nil",
				privKey:     privKey1,
				destination: "3CuDaAXPUQJGLpyaZThy12s4APdd2qXK1k",
				prevTxID:    prevTxId1,
				pkScript:    pkScript1,
				balance:     49664,
				output:      50000,
				netParams: &Params{
					FeeRate: DefaultFeeRate,
					Network: nil,
				},
				wantAmount:              49398,
				wantFeeAmount:           266,
				wantErr:                 true,
				wantWitnessSignatureLen: 72,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				wifPrivateKey, err := btcutil.DecodeWIF(tc.privKey)
				if err != nil {
					require.NoError(t, err)
				}

				pkScriptDecoded, err := hex.DecodeString(tc.pkScript)
				if err != nil {
					require.NoError(t, err)
				}
				forgeIns := []ForgeTxIn{
					{
						Utxo: UTXO{
							TxID:         tc.prevTxID,
							Vout:         0,
							Value:        tc.balance,
							PubKeyScript: pkScriptDecoded,
						},
						WIFPrivKey: wifPrivateKey,
					},
				}
				forgeOuts := []ForgeTxOut{
					{
						Value:   tc.output, // decreased from first met output
						Address: tc.destination,
					},
				}
				redeemTx, sumResult, err := ForgeTx(forgeIns, forgeOuts, tc.netParams)

				if tc.wantErr {
					require.Error(t, err)
					return
				}

				require.NoError(t, err)
				require.NotNil(t, redeemTx)

				assert.Equal(t, tc.wantFeeAmount, sumResult.Fee)
				require.Equal(t, redeemTx.Version, int32(wire.TxVersion))

				require.Len(t, redeemTx.TxIn, 1)
				assert.Equal(t, wantSigScript, redeemTx.TxIn[0].SignatureScript)
				assert.Len(t, redeemTx.TxIn[0].Witness, 2)
				assert.Len(t, redeemTx.TxIn[0].Witness[0], tc.wantWitnessSignatureLen)
				assert.Len(t, redeemTx.TxIn[0].Witness[1], 33)

				require.Len(t, redeemTx.TxOut, 1)
				assert.Equal(t, tc.wantAmount, int(redeemTx.TxOut[0].Value))
				assert.Equal(t, wantPkScript, redeemTx.TxOut[0].PkScript)

				// checking that destination is spendable by private key
				assert.Equal(t, pkScriptFromPrivKey, redeemTx.TxOut[0].PkScript, "pkScript must be spendable by private key")
			})
		}
	})

	t.Run("many to one", func(t *testing.T) {
		wifPrivateKey1, err := btcutil.DecodeWIF(privKey1)
		require.NoError(t, err)
		wifPrivateKey2, err := btcutil.DecodeWIF(privKey2)
		require.NoError(t, err)
		wifPrivateKey3, err := btcutil.DecodeWIF(privKey3)
		require.NoError(t, err)
		wifPrivateKey4, err := btcutil.DecodeWIF(privKey4)
		require.NoError(t, err)
		wifPrivateKey5, err := btcutil.DecodeWIF(privKey5)
		require.NoError(t, err)

		pkScriptDecoded1, err := hex.DecodeString(pkScript1)
		require.NoError(t, err)

		witnessProgram2, err := GetWitnessProgramFromPrivateKey(wifPrivateKey2, testParams.Network)
		require.NoError(t, err)
		pkScript2 := GetPkScriptFromWitnessProgram(witnessProgram2)

		witnessProgram3, err := GetWitnessProgramFromPrivateKey(wifPrivateKey3, testParams.Network)
		require.NoError(t, err)
		pkScript3 := GetPkScriptFromWitnessProgram(witnessProgram3)

		witnessProgram4, err := GetWitnessProgramFromPrivateKey(wifPrivateKey4, testParams.Network)
		require.NoError(t, err)
		pkScript4 := GetPkScriptFromWitnessProgram(witnessProgram4)

		witnessProgram5, err := GetWitnessProgramFromPrivateKey(wifPrivateKey5, testParams.Network)
		require.NoError(t, err)
		pkScript5 := GetPkScriptFromWitnessProgram(witnessProgram5)

		//
		//wifPrivateKey2, err := btcutil.DecodeWIF(privKey2)
		//require.NoError(t, err)
		//
		//witnessProgram3, err := GetWitnessProgramFromPrivateKey(wifPrivateKey3, testParams.Network)
		//require.NoError(t, err)
		//wifPrivateKey3, err := btcutil.DecodeWIF(privKey3)
		//require.NoError(t, err)
		//
		//witnessProgram4, err := GetWitnessProgramFromPrivateKey(wifPrivateKey4, testParams.Network)
		//require.NoError(t, err)
		//wifPrivateKey4, err := btcutil.DecodeWIF(privKey4)
		//require.NoError(t, err)

		//witnessProgram1, err := GetWitnessProgramFromPrivateKey(wifPrivateKey1, testParams.Network)
		//require.NoError(t, err)
		//witnessProgram2, err := GetWitnessProgramFromPrivateKey(wifPrivateKey2, testParams.Network)
		//require.NoError(t, err)
		//witnessProgram3, err := GetWitnessProgramFromPrivateKey(wifPrivateKey3, testParams.Network)
		//require.NoError(t, err)
		//witnessProgram4, err := GetWitnessProgramFromPrivateKey(wifPrivateKey4, testParams.Network)
		//require.NoError(t, err)

		testcases := []struct {
			name      string
			txIns     []ForgeTxIn
			txOut     ForgeTxOut
			netParams *Params

			wantLeastOutput int
			wantLeastFee    int
			wantErr         bool // TODO: refactor to check specific errors
		}{
			{
				name: "ok",
				txIns: []ForgeTxIn{
					generateTxIn(prevTxId1, 0, 1000, pkScriptDecoded1, wifPrivateKey1),
					generateTxIn(prevTxId2, 0, 1000, pkScript2, wifPrivateKey2),
					generateTxIn(prevTxId3, 0, 1000, pkScript3, wifPrivateKey3),
					generateTxIn(prevTxId4, 0, 1000, pkScript4, wifPrivateKey4),
					generateTxIn(prevTxId5, 0, 1000, pkScript5, wifPrivateKey5),
				},
				txOut: ForgeTxOut{
					Value:   5000,
					Address: p2sh1,
				},
				netParams:       testParams,
				wantLeastOutput: 4000,
				wantLeastFee:    900, // ~180 is weight of one input p2wpkh-p2sh
				wantErr:         false,
			},
			{
				name: "ok, all txins have one prev tx, but different vout",
				txIns: []ForgeTxIn{
					generateTxIn(prevTxId1, 0, 1000, pkScriptDecoded1, wifPrivateKey1),
					generateTxIn(prevTxId1, 1, 1000, pkScript2, wifPrivateKey2),
					generateTxIn(prevTxId1, 2, 1000, pkScript3, wifPrivateKey3),
					generateTxIn(prevTxId1, 3, 1000, pkScript4, wifPrivateKey4),
					generateTxIn(prevTxId1, 4, 1000, pkScript5, wifPrivateKey5),
				},
				txOut: ForgeTxOut{
					Value:   5000,
					Address: p2sh1,
				},
				netParams:       testParams,
				wantLeastOutput: 4000,
				wantLeastFee:    900, // ~180 is weight of one input p2wpkh-p2sh, + output + tx itself
				wantErr:         false,
			},
			{
				name: "error, pkscript and privatekey doesn't match",
				txIns: []ForgeTxIn{
					generateTxIn(prevTxId1, 0, 1000, pkScriptDecoded1, wifPrivateKey1),
					generateTxIn(prevTxId2, 0, 1000, pkScriptDecoded1, wifPrivateKey2),
					generateTxIn(prevTxId3, 0, 1000, pkScript3, wifPrivateKey3),
					generateTxIn(prevTxId4, 0, 1000, pkScript4, wifPrivateKey4),
					generateTxIn(prevTxId5, 0, 1000, pkScript5, wifPrivateKey5),
				},
				txOut: ForgeTxOut{
					Value:   5000,
					Address: p2sh1,
				},
				netParams:       testParams,
				wantLeastOutput: 4000,
				wantLeastFee:    900, // ~180 is weight of one input p2wpkh-p2sh
				wantErr:         true,
			},
			{
				name: "error, input isn't sufficient",
				txIns: []ForgeTxIn{
					generateTxIn(prevTxId1, 0, 500, pkScriptDecoded1, wifPrivateKey1),
					generateTxIn(prevTxId2, 0, 100, pkScript2, wifPrivateKey2),
					generateTxIn(prevTxId3, 0, 100, pkScript3, wifPrivateKey3),
					generateTxIn(prevTxId4, 0, 100, pkScript4, wifPrivateKey4),
					generateTxIn(prevTxId5, 0, 100, pkScript5, wifPrivateKey5),
				},
				txOut: ForgeTxOut{
					Value:   5000,
					Address: p2sh1,
				},
				netParams:       testParams,
				wantLeastOutput: 4000,
				wantLeastFee:    900, // ~180 is weight of one input p2wpkh-p2sh
				wantErr:         true,
			},
			{
				name:  "error, input is empty",
				txIns: []ForgeTxIn{},
				txOut: ForgeTxOut{
					Value:   0,
					Address: p2sh1,
				},
				netParams:       testParams,
				wantLeastOutput: 0,
				wantLeastFee:    0, // ~180 is weight of one input p2wpkh-p2sh
				wantErr:         true,
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				redeemTx, sumResult, err := ForgeTx(tc.txIns, []ForgeTxOut{tc.txOut}, tc.netParams)
				if tc.wantErr {
					require.Error(t, err)
					return
				}
				require.NotNil(t, redeemTx)
				require.NoError(t, err)
				assert.Greater(t, sumResult.Fee, tc.wantLeastFee)
				require.Len(t, redeemTx.TxIn, 5)
				require.Len(t, redeemTx.TxOut, 1)
				assert.Greater(t, redeemTx.TxOut[0].Value, int64(tc.wantLeastOutput))
			})
		}
	})
}

// TestGetPkScriptFromWitnessProgram also tests GetWitnessProgramFromPrivateKey
func TestGetPkScriptFromWitnessProgram(t *testing.T) {
	privKey1 := "cMdRNN4Fwmvbictryk69BA5fDGxHqFe7iNDxCC3H9yhxCWoKvUML"
	pkScript1 := "a91490c6addad6abcb929b6edd2833397aed1b5c6f5e87"

	privKey2 := "cNsAQ7t1SFFDvXsLaMZ4xTg9bqK9RZNWnQDHmPGEPpn5QVRgGGXV"
	pkScript2 := "a914481b778229c23b93e685e499ba55d0c0f1bc183b87"

	privKey3 := "cVUJncM2GPMBnb3TFS8zU4CQ1qHgZLRdEwg3iFyZwds3AL3EK56U"
	pkScript3 := "a9145e48546efaa8d0a471ebbe3a190197e58aede88a87"

	privKey4 := "cTrswWxoZEqaPwMizFtnezNk8nKwHaQqC4i6LTeHumQTackhk8Bz"
	pkScript4 := "a914bdacd5e162c6643254ddfd4a7610149256e8753687"

	privKey5 := "cUmudPVY1D5vevqQLkmToJxXWVzgZLW2prpts9DnSsHpqnkFq4kp"
	pkScript5 := "a914e806b73ffa3f86193e126c69ef58c1ec7cd36a2487"

	testcases := []struct {
		privKey      string
		wantPkScript string
		match        bool
	}{
		{
			privKey:      privKey1,
			wantPkScript: pkScript1,
			match:        true,
		},
		{
			privKey:      privKey2,
			wantPkScript: pkScript2,
			match:        true,
		},
		{
			privKey:      privKey3,
			wantPkScript: pkScript3,
			match:        true,
		},
		{
			privKey:      privKey4,
			wantPkScript: pkScript4,
			match:        true,
		},
		{
			privKey:      privKey5,
			wantPkScript: pkScript5,
			match:        true,
		},
		{
			privKey:      privKey1,
			wantPkScript: pkScript2,
			match:        false,
		},
		{
			privKey:      privKey2,
			wantPkScript: pkScript1,
			match:        false,
		},
		{
			privKey:      privKey3,
			wantPkScript: pkScript4,
			match:        false,
		},
		{
			privKey:      privKey4,
			wantPkScript: pkScript5,
			match:        false,
		},
	}

	for _, tc := range testcases {
		wifPrivKey, err := btcutil.DecodeWIF(tc.privKey)
		require.NoError(t, err)

		witnessProgram, err := GetWitnessProgramFromPrivateKey(wifPrivKey, &chaincfg.TestNet3Params)
		require.NoError(t, err)

		pkScript := GetPkScriptFromWitnessProgram(witnessProgram)
		hexPkScript := hex.EncodeToString(pkScript)
		if tc.match {
			assert.Equal(t, tc.wantPkScript, hexPkScript)
		} else {
			assert.NotEqual(t, tc.wantPkScript, hexPkScript)
		}

	}
}

// generateTxIn helper for tests
func generateTxIn(txId string, vout uint32, value int, pkScript []byte, wifPrivateKey *btcutil.WIF) ForgeTxIn {
	return ForgeTxIn{
		Utxo: UTXO{
			TxID:         txId,
			Vout:         vout,
			Value:        value,
			PubKeyScript: pkScript,
		},
		WIFPrivKey: wifPrivateKey,
	}
}
