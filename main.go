package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

func main() {
	// things we need to test:
	// - generating ecdsa key pair
	// - generating rsa key pair
	// - finding existing key pair
	// - generating random bytes

	ctx := context.Background()
	location := os.Args[1]

	switch os.Args[2] {
	// all of the different things we need to test
	case "generate-ecdsa":
		log.Print("Testing ECDSA generation key on HSM")
		log.Print("***********************************")
		key, err := testGenerateKey(ctx, os.Args[3], os.Args[4], kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256)
		if err != nil {
			log.Printf("failed to generate ecdsa: %v", err)
			break
		}
		log.Print("Succeeded!")
		log.Printf("key is: %v", key)
	case "generate-rsa":
		log.Print("Testing RSA generation key on HSM")
		log.Print("***********************************")
		key, err := testGenerateKey(ctx, os.Args[3], os.Args[4], kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256)
		if err != nil {
			log.Printf("failed to generate ecdsa: %v", err)
			break
		}
		log.Print("Succeeded!")
		log.Printf("key is: %v", key)
	case "rand-reader":
		data, err := testRandReader(ctx, location)
		if err != nil {
			log.Printf("rand reader test failed: %v", err)
			break
		}
		log.Print("Succeeded!")
		encoded := make([]byte, hex.EncodedLen(len(data)))
		hex.Encode(encoded, data)
		log.Printf("random hex encoded data is: %s", encoded)
	case "find-keypair":
		handle, err := testFindKeyPair(ctx, []byte(os.Args[5]))
		if err != nil {
			log.Printf("failed to find key pair: %v", err)
			break
		}
		log.Print("Succeeded!")
		log.Printf("handle is: %s", handle)
	}
}

func testGenerateKey(ctx context.Context, keyRing string, keyName string, algo kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (*kmspb.CryptoKey, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	req := kmspb.CreateCryptoKeyRequest{
		Parent: keyRing,
		CryptoKeyId: keyName,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: algo,
			},
		},
	}

	resp, err := client.CreateCryptoKey(ctx, &req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func testRandReader(ctx context.Context, location string) ([]byte, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	req := &kmspb.GenerateRandomBytesRequest{
		// notably, this isn't tied to a specific key ring and/or token, just a location
		Location: location,
		LengthBytes: 1024,
		ProtectionLevel: kmspb.ProtectionLevel_HSM,
	}
	resp, err := client.GenerateRandomBytes(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.GetData(), nil
}

func testFindKeyPair(ctx context.Context, label []byte) (uint, error) {
	return 0, fmt.Errorf("key is not in the HSM; did you specify the label of something that exists in the keyring?")
}
