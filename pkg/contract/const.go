package contract

const (
	TestJST = "JST"
	TestWIN = "WIN"
	TestTRX = "TRX"
)

const (
	USDT = "USDT"
	TRX  = "TRX"
)

type DetailContract struct {
	Contract string
	Types    string
	Decimal  int64
}

func NetworkTestToken() map[string]DetailContract {
	var res = make(map[string]DetailContract)

	res[TestJST] = DetailContract{
		Contract: "TF17BgPaZYbz8oxbjhriubPDsA7ArKoLX3",
		Types:    "TRC20",
		Decimal:  1e18,
	}

	res[TestWIN] = DetailContract{
		Contract: "TU2T8vpHZhCNY8fXGVaHyeZrKm8s6HEXWe",
		Types:    "TRC20",
		Decimal:  1e6,
	}
	res[TestTRX] = DetailContract{
		Contract: "none",
		Types:    "TRX",
		Decimal:  1e6,
	}
	return res
}

func NetworkToken() map[string]DetailContract {

	var res = make(map[string]DetailContract)
	res[USDT] = DetailContract{
		Contract: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
		Decimal:  1e6,
	}
	res[TRX] = DetailContract{
		Contract: "none",
		Types:    "TRX",
		Decimal:  1e6,
	}
	return res
}
