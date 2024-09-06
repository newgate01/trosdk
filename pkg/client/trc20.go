package client

import (
	"fmt"
	"github.com/newgate01/trosdk/pkg/common"
	"math/big"
)

const (
	trc20TransferMethodSignature = "0xa9059cbb"
	trc20ApproveMethodSignature  = "0x095ea7b3"
	trc20TransferEventSignature  = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	trc20NameSignature           = "0x06fdde03"
	trc20SymbolSignature         = "0x95d89b41"
	trc20DecimalsSignature       = "0x313ce567"
	trc20BalanceOf               = "0x70a08231"
	blackHole                    = "410000000000000000000000000000000000000000"
)

func ParseTRC20NumericProperty(data string) (*big.Int, error) {
	if common.Has0xPrefix(data) {
		data = data[2:]
	}
	if len(data) == 64 {
		var n big.Int
		_, ok := n.SetString(data, 16)
		if ok {
			return &n, nil
		}
	}

	if len(data) == 0 {
		return big.NewInt(0), nil
	}

	return nil, fmt.Errorf("cannot parse %s", data)
}
