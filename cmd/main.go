// cmd/main.go
//
// このファイルは、SCRAM-SHA256 認証サーバーに対するクライアント側の実装例です。
// 本実装では、サーバー (main.go で起動中) の "/scram" エンドポイントに対して、
// SCRAM 認証で要求される "client-first" および "client-final" メッセージを順次送信し、
// 認証ハンドシェイクを実施します。
//
// 実装の流れ:
// 1. クライアントは "client-first" メッセージ ("n,,n=<username>,r=<clientNonce>") をサーバーに送信します。
//    サーバーはこれに応答して、"server-first" メッセージとして、combined nonce、salt、反復回数 (i) を返します。
// 2. 受信した情報（combined nonce, salt, i）を用いて、PBKDF2、HMAC、XOR 操作により client proof を生成します。
//    生成した client proof を含む "client-final" メッセージ ("c=<GS2 header>,r=<combinednonce>,p=<clientProof>") をサーバーに送信します。
// 3. サーバーは client proof の検証に成功すると、server signature を含む "server-final" メッセージを返し、認証が完了します.
//
// 参考資料:
//  - RFC 5802: https://tools.ietf.org/html/rfc5802
//  - Go net/http パッケージ: https://golang.org/pkg/net/http/
//  - Go 公式ドキュメント: https://golang.org/doc/

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	iterationCount = 4096
	serverURL      = "http://localhost:8080/scram"
)

// ScramRequest はサーバーに送信するリクエストの JSON 形式を定義します。
type ScramRequest struct {
	Step    string `json:"step"`    // 認証ステップ ("client-first" または "client-final")
	Message string `json:"message"` // 送信する SCRAM メッセージの内容
}

// ScramResponse はサーバーから返されるレスポンスの JSON 形式を定義します。
type ScramResponse struct {
	Message string `json:"message"`         // サーバーからのレスポンスメッセージ
	Error   string `json:"error,omitempty"` // エラー発生時の詳細（エラーなしの場合は空文字）
}

// createNonce は指定された長さのランダムな英数字文字列 (nonce) を生成します。
func createNonce(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// hmacSha256 は HMAC-SHA256 アルゴリズムを使用してデータのハッシュを計算します。
func hmacSha256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// sha256Hash はデータに対して SHA256 ハッシュ値を計算します。
func sha256Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// xorBytes は 2 つのバイトスライス間で XOR 演算を行います。
func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	xor := make([]byte, n)
	for i := 0; i < n; i++ {
		xor[i] = a[i] ^ b[i]
	}
	return xor
}

// sendScramRequest は指定された ScramRequest を JSON としてサーバーに送信し、
// ScramResponse を受信して返します。
func sendScramRequest(req ScramRequest) (ScramResponse, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return ScramResponse{}, err
	}
	resp, err := http.Post(serverURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return ScramResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ScramResponse{}, err
	}
	var scramResp ScramResponse
	err = json.Unmarshal(body, &scramResp)
	if err != nil {
		return ScramResponse{}, err
	}
	return scramResp, nil
}

// main 関数は、SCRAM 認証プロセスを順次実施するクライアントのエントリーポイントです。
func main() {
	// クライアント側の認証情報（デモ用）
	username := "user"
	password := "pencil"

	// Step 1: "client-first" メッセージの送信
	clientNonce := createNonce(16)
	clientFirstMsg := fmt.Sprintf("n,,n=%s,r=%s", username, clientNonce)
	req := ScramRequest{
		Step:    "client-first",
		Message: clientFirstMsg,
	}
	fmt.Println("Sending client-first message:", clientFirstMsg)
	resp, err := sendScramRequest(req)
	if err != nil || resp.Error != "" {
		fmt.Println("Error in client-first:", err, resp.Error)
		os.Exit(1)
	}
	serverFirstMsg := resp.Message
	fmt.Println("Received server-first message:", serverFirstMsg)

	// Step 2: サーバーからの "server-first" メッセージをパース
	// 期待形式: "r=<combinednonce>,s=<salt>,i=<iteration>"
	parts := strings.Split(serverFirstMsg, ",")
	var combinedNonce, saltB64 string
	var iter int
	for _, part := range parts {
		if strings.HasPrefix(part, "r=") {
			combinedNonce = strings.TrimPrefix(part, "r=")
		} else if strings.HasPrefix(part, "s=") {
			saltB64 = strings.TrimPrefix(part, "s=")
		} else if strings.HasPrefix(part, "i=") {
			fmt.Sscanf(strings.TrimPrefix(part, "i="), "%d", &iter)
		}
	}
	if combinedNonce == "" || saltB64 == "" || iter == 0 {
		fmt.Println("Invalid server-first message")
		os.Exit(1)
	}

	// Step 3: "client-final" メッセージの作成
	//  c は Base64 エンコードされた GS2 ヘッダー。 "n,," の場合、"biws" です。
	channelBinding := "biws"
	clientFinalWithoutProof := fmt.Sprintf("c=%s,r=%s", channelBinding, combinedNonce)
	// client-first bare は "n=<username>,r=<clientNonce>" であるため、再生成します。
	clientFirstBare := fmt.Sprintf("n=%s,r=%s", username, clientNonce)
	// 認証メッセージは、client-first bare, server-first message, client-final (証明値除く) の連結です。
	authMessage := fmt.Sprintf("%s,%s,%s", clientFirstBare, serverFirstMsg, clientFinalWithoutProof)

	// PBKDF2 による salted password の導出
	saltBytes, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		fmt.Println("Failed to decode salt:", err)
		os.Exit(1)
	}
	saltedPassword := pbkdf2.Key([]byte(password), saltBytes, iter, 32, sha256.New)
	clientKey := hmacSha256(saltedPassword, "Client Key")
	storedKey := sha256Hash(clientKey)
	clientSignature := hmacSha256(storedKey, authMessage)
	clientProof := xorBytes(clientKey, clientSignature)
	clientProofB64 := base64.StdEncoding.EncodeToString(clientProof)

	clientFinalMsg := fmt.Sprintf("c=%s,r=%s,p=%s", channelBinding, combinedNonce, clientProofB64)
	req = ScramRequest{
		Step:    "client-final",
		Message: clientFinalMsg,
	}
	fmt.Println("Sending client-final message:", clientFinalMsg)
	resp, err = sendScramRequest(req)
	if err != nil || resp.Error != "" {
		fmt.Println("Error in client-final:", err, resp.Error)
		os.Exit(1)
	}
	fmt.Println("Authentication successful, server final message:", resp.Message)
}
