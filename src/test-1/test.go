package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

type TestCC struct {
}

func main() {
	err := shim.Start(new(TestCC))
	if err != nil {
		fmt.Printf("Error starting chaincode: %s", err)
	}
}

func (tcc *TestCC) Init(stub shim.ChaincodeStubInterface) pb.Response {
	// add the initialization logic and process
	return shim.Success([]byte("init test cc"))
}

func (tcc *TestCC) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	// dispatch the function invocation to different methods
	function, args := stub.GetFunctionAndParameters()

	switch function {
	case "test":
		return tcc.test(stub, args)
	default:
		return shim.Error("Invalid function name.")
	}
}

func (tcc *TestCC) test(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2.")
	}

	data := args[0]
	sign := args[1]

	if !verify([]byte(data), sign) {
		return shim.Error("Invalid signature.")
	}

	if err := stub.PutState(data, []byte(sign)); err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success([]byte("success"))
}

func verify(data []byte, sign string) bool {
	array := strings.Split(sign, ":")
	if len(array) != 3 {
		return false
	}
	r, ok := new(big.Int).SetString(array[0], 16)
	if !ok {
		return false
	}
	s, ok := new(big.Int).SetString(array[1], 16)
	if !ok {
		return false
	}
	publicKey, err := publicKey(array[2])
	if err != nil {
		return false
	}
	return ecdsa.Verify(publicKey, data, r, s)
}

func publicKey(pub string) (*ecdsa.PublicKey, error) {
	if strings.Index(pub, "0x") == -1 {
		pub = "0x" + pub
	}
	pubBytes, err := Decode(pub)
	if err != nil {
		return nil, err
	}
	publicKey, err := UnmarshalPubkey(pubBytes)
	return publicKey, nil
}

// Decode decodes a hex string with 0x prefix.
func Decode(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, errors.New("empty hex string")
	}
	if !has0xPrefix(input) {
		return nil, errors.New("hex string without 0x prefix")
	}
	b, err := hex.DecodeString(input[2:])
	return b, err
}

func has0xPrefix(input string) bool {
	return len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')
}

func UnmarshalPubkey(pub []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(S256(), pub)
	if x == nil {
		return nil, errors.New("invalid secp256k1 public key")
	}
	return &ecdsa.PublicKey{Curve: S256(), X: x, Y: y}, nil
}

// S256 returns an instance of the secp256k1 curve.
func S256() elliptic.Curve {
	return secp256k1.S256()
}
