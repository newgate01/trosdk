package utils

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/newgate01/trosdk/core"
	"github.com/newgate01/trosdk/pkg/common"
	"github.com/newgate01/trosdk/pkg/hexutil"
	"google.golang.org/protobuf/proto"
	"math/big"
	"time"
)

func GetData(data []byte, start, size uint64) []byte {
	length := uint64(len(data))
	if start > length {
		start = length
	}
	end := start + size
	if end > length {
		end = length
	}
	return RightPadBytes(data[start:end], int(size))
}
func GetUnPaddingData(data []byte, start, size uint64) []byte {
	length := uint64(len(data))
	if start > length {
		start = length
	}
	end := start + size
	if end > length {
		end = length
	}
	data = data[start:end]

	for i, v := range data {
		if v == 0 {
			continue
		}
		data = data[i:]
		break
	}

	return data
}

// RightPadBytes zero-pads slice to the right up to length l.
func RightPadBytes(slice []byte, l int) []byte {
	if l <= len(slice) {
		return slice
	}

	padded := make([]byte, l)
	copy(padded, slice)

	return padded
}

// SignTransaction 签名交易
func SignTransaction(transaction *core.Transaction, key *ecdsa.PrivateKey) ([]byte, error) {
	transaction.GetRawData().Timestamp = time.Now().UnixNano() / 1000000
	rawData, err := proto.Marshal(transaction.GetRawData())
	if err != nil {
		return nil, err
	}
	h256h := sha256.New()
	h256h.Write(rawData)
	hash := h256h.Sum(nil)
	contractList := transaction.GetRawData().GetContract()
	for range contractList {
		signature, err := crypto.Sign(hash, key)
		if err != nil {
			return nil, err
		}
		transaction.Signature = append(transaction.Signature, signature)
	}
	return hash, nil
}

func ProcessBalanceOfParameter(addr string) (data []byte) {
	methodID, _ := hexutil.Decode("70a08231")
	add, _ := common.DecodeCheck(addr)
	paddedAddress := common.LeftPadBytes(add[1:], 32)
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	return
}

// 处理合约转账参数
func processTransferParameter(to string, amount int64) (data []byte) {
	methodID, _ := hexutil.Decode("a9059cbb")
	addr, _ := common.DecodeCheck(to)
	paddedAddress := common.LeftPadBytes(addr[1:], 32)
	amountBig := new(big.Int).SetInt64(amount)
	paddedAmount := common.LeftPadBytes(amountBig.Bytes(), 32)
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)
	return
}
