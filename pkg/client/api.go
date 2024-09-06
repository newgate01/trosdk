package client

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/newgate01/trosdk/core"
	"github.com/newgate01/trosdk/pkg/address"
	"github.com/newgate01/trosdk/pkg/common"
	"github.com/shopspring/decimal"
	"math/big"

	crypto "github.com/newgate01/trosdk/pkg/crypto"
	"github.com/newgate01/trosdk/pkg/hexutil"
	"github.com/newgate01/trosdk/pkg/utils"
	"strconv"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/newgate01/trosdk/api"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"time"
)

const (
	RetryCount       = 5
	Backoff          = 100
	TypeTRX          = "TRX"
	TypeTRC20        = "TRC20"
	TypeTrc10        = "TRC10"
	TeeLimit   int64 = 1000000000
)

type Api struct {
	a    *TronGrpcConn
	wait *RateLimiter
}

type TronGrpcConn struct {
	api.WalletClient
}

func NewApiConn(address string) Api {
	cli := newGrpcConn(address, 6)

	conn := newTronGrpcConn(cli)

	return Api{a: conn, wait: NewLimiter(80, 1)}
}

func (p Api) A() *TronGrpcConn {

	p.wait.RateWait()
	return p.a
}

func newTronGrpcConn(conn *grpc.ClientConn) *TronGrpcConn {
	return &TronGrpcConn{
		api.NewWalletClient(conn),
	}
}

func newGrpcConn(addr string, receiveSize int) *grpc.ClientConn {
	var (
		err  error
		m    = 1024 * 1024
		conn *grpc.ClientConn
	)
	opts := []grpc_retry.CallOption{
		grpc_retry.WithBackoff(grpc_retry.BackoffLinear(Backoff * time.Millisecond)),
		grpc_retry.WithCodes(codes.NotFound, codes.Aborted, codes.Unavailable),
	}
	conn, err = grpc.Dial(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(receiveSize*m)),
		grpc.WithUnaryInterceptor(
			grpc_middleware.ChainUnaryClient(
				grpc_retry.UnaryClientInterceptor(opts...))),
	)
	if err != nil {
		log.Panic("grpc conn error ==>", err)
	}
	if state := conn.GetState(); state == connectivity.Shutdown {
		log.Panic("grpc conn shutdown ==>")
	}
	return conn
}

type RateLimiter struct {
	r *rate.Limiter
}

func NewLimiter(r time.Duration, b int) *RateLimiter {

	limit := rate.Every(r * time.Millisecond)
	return &RateLimiter{
		rate.NewLimiter(limit, b),
	}
}

func (p *RateLimiter) RateWait() {
	p.r.Wait(context.Background())
}
func (p *RateLimiter) RateBurst() int {
	return p.r.Burst()
}

func (p *RateLimiter) RateLimit() float64 {
	return float64(p.r.Limit())
}

func (p Api) Send(key *ecdsa.PrivateKey, types, contract string, decimalLen int64, amount decimal.Decimal, to string) (string, error) {

	var amountDecimal = decimal.NewFromInt(decimalLen)
	amountaInt := amount.Mul(amountDecimal).IntPart()
	switch types {
	case TypeTrc10:
		return p.TransferAsset(key, contract, to, amountaInt)
	case TypeTRX:
		return p.Transfer(key, to, amountaInt)
	case TypeTRC20:
		data := ProcessTransferParameter(to, amountaInt)
		return p.TransferContract(key, contract, data, TeeLimit)
	}
	return "", fmt.Errorf("the type %s not support now", types)
}

func timeoutContext() context.Context {

	return context.Background()
}
func (p Api) ListWitnesses() *api.WitnessList {

	witnessList, err := p.A().ListWitnesses(timeoutContext(),
		new(api.EmptyMessage), grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("get witnesses error: %v\n", err)
	}

	return witnessList
}

func (p Api) ListNodes() *api.NodeList {
	nodeList, err := p.A().ListNodes(timeoutContext(),
		new(api.EmptyMessage), grpc_retry.WithMax(RetryCount))
	if err != nil {
		log.Fatalf("get nodes error: %v\n", err)
	}
	return nodeList
}

func (p Api) GetNodeInfo() (*core.NodeInfo, error) {
	node, err := p.A().GetNodeInfo(timeoutContext(), new(api.EmptyMessage), grpc_retry.WithMax(RetryCount))
	if err != nil {
		return nil, err
	}
	return node, err
}

func (p Api) GetAccount(address string) (*core.Account, error) {
	account := new(core.Account)
	var err error
	account.Address, err = common.DecodeCheck(address)
	if err != nil {
		return nil, err
	}
	result, err := p.A().GetAccount(timeoutContext(), account, grpc_retry.WithMax(RetryCount))
	return result, err
}

func (p Api) GetNowBlock() (*api.BlockExtention, error) {
	result, err := p.A().GetNowBlock2(timeoutContext(), new(api.EmptyMessage), grpc_retry.WithMax(RetryCount))
	return result, err
}

func (p Api) GetAssetIssueByAccount(address string) *api.AssetIssueList {
	account := new(core.Account)

	account.Address, _ = common.DecodeCheck(address)

	result, err := p.A().GetAssetIssueByAccount(timeoutContext(),
		account, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("get asset issue by account error: %v", err)
	}

	return result
}

func (p Api) GetNextMaintenanceTime() *api.NumberMessage {

	result, err := p.A().GetNextMaintenanceTime(timeoutContext(),
		new(api.EmptyMessage), grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("get next maintenance time error: %v", err)
	}

	return result
}

func (p Api) TotalTransaction() *api.NumberMessage {

	result, err := p.A().TotalTransaction(timeoutContext(),
		new(api.EmptyMessage), grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("total transaction error: %v", err)
	}

	return result
}

func (p Api) GetAccountNet(address string) *api.AccountNetMessage {
	account := new(core.Account)

	account.Address, _ = common.DecodeCheck(address)

	result, err := p.A().GetAccountNet(timeoutContext(), account, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("get account net error: %v", err)
	}

	return result
}

func (p Api) GetAssetIssueByName(name string) *core.AssetIssueContract {

	assetName := new(api.BytesMessage)
	assetName.Value = []byte(name)

	result, err := p.A().GetAssetIssueByName(timeoutContext(), assetName, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("get asset issue by name error: %v", err)
	}

	return result
}

func (p Api) GetBlockByNum(num int64) (*api.BlockExtention, error) {
	numMessage := new(api.NumberMessage)
	numMessage.Num = num
	result, err := p.A().GetBlockByNum2(timeoutContext(), numMessage, grpc_retry.WithMax(RetryCount))
	return result, err
}

func (p Api) GetBlockById(id string) *core.Block {
	blockId := new(api.BytesMessage)
	var err error

	blockId.Value, err = hexutil.Decode(id)

	if err != nil {
		log.Fatalf("get block by id error: %v", err)
	}

	result, err := p.A().GetBlockById(timeoutContext(), blockId, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("get block by id error: %v", err)
	}

	return result
}

func (p Api) GetAssetIssueList() *api.AssetIssueList {

	result, err := p.A().GetAssetIssueList(timeoutContext(), new(api.EmptyMessage), grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("get asset issue list error: %v", err)
	}

	return result
}

func (p Api) GetBlockByLimitNext(start, end int64) (*api.BlockListExtention, error) {
	blockLimit := new(api.BlockLimit)
	blockLimit.StartNum = start
	blockLimit.EndNum = end
	result, err := p.A().GetBlockByLimitNext2(timeoutContext(), blockLimit, grpc_retry.WithMax(RetryCount))
	return result, err
}

func (p Api) GetTransactionById(id string) (*core.Transaction, error) {
	transactionId := new(api.BytesMessage)
	var err error
	transactionId.Value, err = hexutil.Decode(id)
	if err != nil {
		return nil, err
	}
	result, err := p.A().GetTransactionById(timeoutContext(), transactionId, grpc_retry.WithMax(RetryCount))
	return result, err
}

func (p Api) GetTransactionInfoById(id string) (*core.TransactionInfo, error) {
	transactionId := new(api.BytesMessage)
	var err error
	transactionId.Value, err = hexutil.Decode(id)
	if err != nil {
		return nil, err
	}
	result, err := p.A().GetTransactionInfoById(timeoutContext(), transactionId, grpc_retry.WithMax(RetryCount))
	return result, err
}

func (p Api) GetBlockByLatestNum(num int64) (*api.BlockListExtention, error) {
	numMessage := new(api.NumberMessage)
	numMessage.Num = num
	result, err := p.A().GetBlockByLatestNum2(timeoutContext(), numMessage, grpc_retry.WithMax(RetryCount))
	return result, err
}

func (p Api) CreateAccount(ownerKey *ecdsa.PrivateKey,
	accountAddress string) *api.Return {

	accountCreateContract := new(core.AccountCreateContract)
	accountCreateContract.OwnerAddress = crypto.PublicKeyToAddress(ownerKey.PublicKey).Bytes()
	accountCreateContract.AccountAddress, _ = common.DecodeCheck(accountAddress)

	accountCreateTransaction, err := p.A().CreateAccount(timeoutContext(), accountCreateContract, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("create account error: %v", err)
	}

	if accountCreateTransaction == nil || len(accountCreateTransaction.GetRawData().GetContract()) == 0 {
		log.Fatalf("create account error: invalid transaction")
	}

	utils.SignTransaction(accountCreateTransaction, ownerKey)

	result, err := p.A().BroadcastTransaction(timeoutContext(),
		accountCreateTransaction, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("create account error: %v", err)
	}

	return result
}

func (p Api) UpdateAccount(ownerKey *ecdsa.PrivateKey,
	accountName string) *api.Return {
	var err error
	accountUpdateContract := new(core.AccountUpdateContract)
	accountUpdateContract.AccountName = []byte(accountName)
	accountUpdateContract.OwnerAddress = crypto.PublicKeyToAddress(ownerKey.
		PublicKey).Bytes()

	accountUpdateTransaction, err := p.A().UpdateAccount(timeoutContext(), accountUpdateContract, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("update account error: %v", err)
	}

	if accountUpdateTransaction == nil || len(accountUpdateTransaction.GetRawData().GetContract()) == 0 {
		log.Fatalf("update account error: invalid transaction")
	}

	utils.SignTransaction(accountUpdateTransaction, ownerKey)

	result, err := p.A().BroadcastTransaction(timeoutContext(),
		accountUpdateTransaction, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("update account error: %v", err)
	}

	return result
}

func (p Api) Transfer(ownerKey *ecdsa.PrivateKey, toAddress string, amount int64) (string, error) {
	transferContract := new(core.TransferContract)
	transferContract.OwnerAddress = crypto.PublicKeyToAddress(ownerKey.
		PublicKey).Bytes()
	transferContract.ToAddress, _ = common.DecodeCheck(toAddress)
	transferContract.Amount = amount

	transferTransactionEx, err := p.A().CreateTransaction2(timeoutContext(), transferContract, grpc_retry.WithMax(RetryCount))

	var txid string
	if err != nil {
		return txid, err
	}
	transferTransaction := transferTransactionEx.Transaction
	if transferTransaction == nil || len(transferTransaction.
		GetRawData().GetContract()) == 0 {
		return txid, fmt.Errorf("transfer error: invalid transaction")
	}
	hash, err := utils.SignTransaction(transferTransaction, ownerKey)
	if err != nil {
		return txid, err
	}
	txid = hexutil.Encode(hash)

	result, err := p.A().BroadcastTransaction(timeoutContext(),
		transferTransaction, grpc_retry.WithMax(RetryCount))
	if err != nil {
		return "", err
	}
	if !result.Result {
		return "", fmt.Errorf("api get false the msg: %v", result.String())
	}
	return txid, err
}

func (p Api) TransferAsset(ownerKey *ecdsa.PrivateKey, AssetName, toAddress string, amount int64) (string, error) {
	transferContract := new(core.TransferAssetContract)
	transferContract.OwnerAddress = crypto.PublicKeyToAddress(ownerKey.
		PublicKey).Bytes()
	transferContract.ToAddress, _ = common.DecodeCheck(toAddress)
	transferContract.AssetName, _ = common.DecodeCheck(AssetName)
	transferContract.Amount = amount

	transferTransactionEx, err := p.A().TransferAsset2(timeoutContext(), transferContract, grpc_retry.WithMax(RetryCount))

	var txid string
	if err != nil {
		return txid, err
	}
	transferTransaction := transferTransactionEx.Transaction
	if transferTransaction == nil || len(transferTransaction.GetRawData().GetContract()) == 0 {
		return txid, fmt.Errorf("transfer error: invalid transaction")
	}
	hash, err := utils.SignTransaction(transferTransaction, ownerKey)
	if err != nil {
		return txid, err
	}
	txid = hexutil.Encode(hash)

	result, err := p.A().BroadcastTransaction(timeoutContext(),
		transferTransaction, grpc_retry.WithMax(RetryCount))
	if err != nil {
		return "", err
	}
	if !result.Result {
		return "", fmt.Errorf("api get false the msg: %v", result.String())
	}
	return txid, err
}
func (p Api) SendTransferTrc20(privateKey, contract, to string) {

}

func (p Api) TransferContract(ownerKey *ecdsa.PrivateKey, Contract string, data []byte, feeLimit int64) (string, error) {
	transferContract := new(core.TriggerSmartContract)
	transferContract.OwnerAddress = crypto.PublicKeyToAddress(ownerKey.PublicKey).Bytes()
	transferContract.ContractAddress, _ = common.DecodeCheck(Contract)
	transferContract.Data = data
	transferTransactionEx, err := p.A().TriggerConstantContract(timeoutContext(), transferContract, grpc_retry.WithMax(RetryCount))
	var txid string
	if err != nil {
		return txid, err
	}
	transferTransaction := transferTransactionEx.Transaction
	if transferTransaction == nil || len(transferTransaction.GetRawData().GetContract()) == 0 {
		return txid, fmt.Errorf("transfer error: invalid transaction")
	}
	if feeLimit > 0 {
		transferTransaction.RawData.FeeLimit = feeLimit
	}

	hash, err := utils.SignTransaction(transferTransaction, ownerKey)
	if err != nil {
		return txid, err
	}
	txid = hexutil.Encode(hash)

	result, err := p.A().BroadcastTransaction(timeoutContext(),
		transferTransaction, grpc_retry.WithMax(RetryCount))
	if err != nil {
		return "", err
	}
	if !result.Result {
		return "", fmt.Errorf("api get false the msg: %v", result.String())
	}
	return txid, err
}
func (p Api) GetTrxBalance(address string) (*big.Int, error) {
	var (
		res *big.Int
		err error
	)
	ac, err := p.GetAccount(address)
	if err != nil {
		return nil, err
	}
	res = decimal.NewFromInt(ac.Balance).BigInt()
	return res, err
}
func (p Api) GetTrc20Balance(Contract string, addrReqData []byte) (*big.Int, error) {
	transferContract := new(core.TriggerSmartContract)
	transferContract.OwnerAddress = address.HexToAddress("410000000000000000000000000000000000000000").Bytes()
	transferContract.ContractAddress, _ = common.DecodeCheck(Contract)
	transferContract.Data = addrReqData

	transferTransactionEx, err := p.A().TriggerConstantContract(timeoutContext(), transferContract, grpc_retry.WithMax(RetryCount))
	if err != nil {
		return nil, err
	}

	if transferTransactionEx == nil || len(transferTransactionEx.GetConstantResult()) == 0 {
		return nil, fmt.Errorf("GetConstantResult error: invalid TriggerConstantContract")
	}

	if len(transferTransactionEx.GetConstantResult()[0]) == 0 {
		return big.NewInt(0), nil
	}

	data := common.BytesToHexString(transferTransactionEx.GetConstantResult()[0])

	return ParseTRC20NumericProperty(data)

}

func (p Api) GetConstantResultOfContract(ownerKey *ecdsa.PrivateKey, Contract string, data []byte) ([][]byte, error) {
	transferContract := new(core.TriggerSmartContract)
	transferContract.OwnerAddress = crypto.PublicKeyToAddress(ownerKey.PublicKey).Bytes()
	transferContract.ContractAddress, _ = common.DecodeCheck(Contract)
	transferContract.Data = data
	transferTransactionEx, err := p.A().TriggerConstantContract(timeoutContext(), transferContract, grpc_retry.WithMax(RetryCount))
	if err != nil {
		return nil, err
	}
	if transferTransactionEx == nil || len(transferTransactionEx.GetConstantResult()) == 0 {
		return nil, fmt.Errorf("GetConstantResult error: invalid TriggerConstantContract")
	}
	return transferTransactionEx.GetConstantResult(), err
}

func (p Api) FreezeBalance(ownerKey *ecdsa.PrivateKey,
	frozenBalance, frozenDuration int64) *api.Return {
	freezeBalanceContract := new(core.FreezeBalanceContract)
	freezeBalanceContract.OwnerAddress = crypto.PublicKeyToAddress(ownerKey.
		PublicKey).Bytes()
	freezeBalanceContract.FrozenBalance = frozenBalance
	freezeBalanceContract.FrozenDuration = frozenDuration

	freezeBalanceTransaction, err := p.A().FreezeBalance(timeoutContext(), freezeBalanceContract, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("freeze balance error: %v", err)
	}

	if freezeBalanceTransaction == nil || len(freezeBalanceTransaction.
		GetRawData().GetContract()) == 0 {
		log.Fatalf("freeze balance error: invalid transaction")
	}

	utils.SignTransaction(freezeBalanceTransaction, ownerKey)

	result, err := p.A().BroadcastTransaction(timeoutContext(),
		freezeBalanceTransaction, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("freeze balance error: %v", err)
	}

	return result
}

func (p Api) UnfreezeBalance(ownerKey *ecdsa.PrivateKey) *api.Return {
	unfreezeBalanceContract := new(core.UnfreezeBalanceContract)
	unfreezeBalanceContract.OwnerAddress = crypto.PublicKeyToAddress(ownerKey.PublicKey).Bytes()

	unfreezeBalanceTransaction, err := p.A().UnfreezeBalance(timeoutContext(), unfreezeBalanceContract, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("unfreeze balance error: %v", err)
	}

	if unfreezeBalanceTransaction == nil || len(unfreezeBalanceTransaction.
		GetRawData().GetContract()) == 0 {
		log.Fatalf("unfreeze balance error: invalid transaction")
	}
	utils.SignTransaction(unfreezeBalanceTransaction, ownerKey)
	result, err := p.A().BroadcastTransaction(timeoutContext(),
		unfreezeBalanceTransaction, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("unfreeze balance error: %v", err)
	}

	return result
}

func (p Api) CreateAssetIssue(ownerKey *ecdsa.PrivateKey,
	name, description, urlStr string, totalSupply, startTime, endTime,
	FreeAssetNetLimit,
	PublicFreeAssetNetLimit int64, trxNum,
	icoNum, voteScore int32, frozenSupply map[string]string) *api.Return {
	assetIssueContract := new(core.AssetIssueContract)

	assetIssueContract.OwnerAddress = crypto.PublicKeyToAddress(ownerKey.
		PublicKey).Bytes()

	assetIssueContract.Name = []byte(name)

	if totalSupply <= 0 {
		log.Fatalf("create asset issue error: total supply <= 0")
	}
	assetIssueContract.TotalSupply = totalSupply

	if trxNum <= 0 {
		log.Fatalf("create asset issue error: trxNum <= 0")
	}
	assetIssueContract.TrxNum = trxNum

	if icoNum <= 0 {
		log.Fatalf("create asset issue error: num <= 0")
	}
	assetIssueContract.Num = icoNum

	now := time.Now().UnixNano() / 1000000
	if startTime <= now {
		log.Fatalf("create asset issue error: start time <= current time")
	}
	assetIssueContract.StartTime = startTime

	if endTime <= startTime {
		log.Fatalf("create asset issue error: end time <= start time")
	}
	assetIssueContract.EndTime = endTime

	if FreeAssetNetLimit < 0 {
		log.Fatalf("create asset issue error: free asset net limit < 0")
	}
	assetIssueContract.FreeAssetNetLimit = FreeAssetNetLimit

	if PublicFreeAssetNetLimit < 0 {
		log.Fatalf("create asset issue error: public free asset net limit < 0")
	}
	assetIssueContract.PublicFreeAssetNetLimit = PublicFreeAssetNetLimit

	assetIssueContract.VoteScore = voteScore
	assetIssueContract.Description = []byte(description)
	assetIssueContract.Url = []byte(urlStr)

	for key, value := range frozenSupply {
		amount, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			log.Fatalf("create asset issue error: convert error: %v", err)
		}
		days, err := strconv.ParseInt(key, 10, 64)
		if err != nil {
			log.Fatalf("create asset issue error: convert error: %v", err)
		}
		assetIssueContractFrozenSupply := new(core.
			AssetIssueContract_FrozenSupply)
		assetIssueContractFrozenSupply.FrozenAmount = amount
		assetIssueContractFrozenSupply.FrozenDays = days
		assetIssueContract.FrozenSupply = append(assetIssueContract.
			FrozenSupply, assetIssueContractFrozenSupply)
	}

	assetIssueTransaction, err := p.A().CreateAssetIssue(timeoutContext(), assetIssueContract, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("create asset issue error: %v", err)
	}

	if assetIssueTransaction == nil || len(assetIssueTransaction.
		GetRawData().GetContract()) == 0 {
		log.Fatalf("create asset issue error: invalid transaction")
	}

	utils.SignTransaction(assetIssueTransaction, ownerKey)

	result, err := p.A().BroadcastTransaction(timeoutContext(),
		assetIssueTransaction, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("create asset issue error: %v", err)
	}

	return result
}

func (p Api) UpdateAssetIssue(ownerKey *ecdsa.PrivateKey,
	description, urlStr string,
	newLimit, newPublicLimit int64) *api.Return {

	updateAssetContract := new(core.UpdateAssetContract)

	updateAssetContract.OwnerAddress = crypto.PublicKeyToAddress(ownerKey.
		PublicKey).Bytes()

	updateAssetContract.Description = []byte(description)
	updateAssetContract.Url = []byte(urlStr)
	updateAssetContract.NewLimit = newLimit
	updateAssetContract.NewPublicLimit = newPublicLimit

	updateAssetTransaction, err := p.A().UpdateAsset(timeoutContext(), updateAssetContract, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("update asset issue error: %v", err)
	}

	if updateAssetTransaction == nil || len(updateAssetTransaction.
		GetRawData().GetContract()) == 0 {
		log.Fatalf("update asset issue error: invalid transaction")
	}

	utils.SignTransaction(updateAssetTransaction, ownerKey)

	result, err := p.A().BroadcastTransaction(timeoutContext(),
		updateAssetTransaction, grpc_retry.WithMax(RetryCount))

	if err != nil {
		log.Fatalf("update asset issue error: %v", err)
	}

	return result
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
func ProcessTransferParameter(to string, amount int64) (data []byte) {
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
