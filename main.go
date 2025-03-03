// main.go
//
// このファイルは、SCRAM-SHA256 認証サーバーのエントリーポイントです。
// 本実装は RFC 5802 に基づいた SCRAM 認証のハンドシェイク処理を実現します。
// サーバーはクライアントからの認証リクエスト ("client-first" および "client-final") を処理し、
// 認証成功時にはサーバー署名を返します.
//
// 各関数の説明は以下のとおりです:
//
// ● createNonce(n int) string
//   - 指定された長さ n のランダムな英数字文字列 (nonce) を生成します。
//   - セッションごとの nonce やサーバー nonce の生成に使用します。
//
// ● hmacSha256(key []byte, data string) []byte
//   - HMAC-SHA256 アルゴリズムを用いて、指定されたキーとデータのハッシュ値を計算します。
//   - 認証に必要な署名およびキーの導出に使用します。
//
// ● sha256Hash(data []byte) []byte
//   - データに対して SHA256 ハッシュ値を計算します。
//   - PBKDF2 から導出されたクライアントキーのハッシュ (StoredKey) 計算に使用します。
//
// ● xorBytes(a, b []byte) []byte
//   - 2 つのバイトスライスの XOR 演算を行い、その結果を返します。
//   - クライアント証明値から元のクライアントキーを復元するために用います。
//
// ● scramHandler(w http.ResponseWriter, r *http.Request)
//   - "/scram" エンドポイントに対する HTTP POST リクエストを処理します。
//   - リクエストボディから JSON をパースし、認証ステップ ("client-first" または "client-final")
//     に応じて handleClientFirst または handleClientFinal を呼び出します。
//
// ● handleClientFirst(w http.ResponseWriter, message string)
//   - クライアントから送信された "client-first" メッセージ (例: "n,,n=<username>,r=<clientNonce>") を処理します。
//   - ユーザー名とクライアント nonce の検証を行い、サーバー nonce および salt を生成。
//   - PBKDF2 を使って salted password を導出し、クライアント検証用の StoredKey と
//     サーバー署名用の ServerKey を計算します。
//   - セッション情報を保存し、"server-first" メッセージ (combined nonce, salt, 反復回数) を返します。
//
// ● handleClientFinal(w http.ResponseWriter, message string)
//   - クライアントから送信された "client-final" メッセージ (例: "c=<base64>,r=<combinedNonce>,p=<clientProof>")
//     を処理します。
//   - セッション情報から認証メッセージを再構築し、クライアント証明値を検証します。
//   - 検証成功時にはサーバー署名 (server signature) を生成し、"server-final" メッセージとして返します。
//   - 認証失敗の場合はエラーを返します。
//
// ● writeResponse(w http.ResponseWriter, resp ScramResponse)
//   - ScramResponse オブジェクトを JSON 形式にシリアライズして、HTTP レスポンスとして返します。
//
// ● main()
//   - サーバーのメイン関数です。
//   - "/scram" エンドポイントに対して scramHandler を登録し、ポート 8080 で HTTP サーバーを起動します。
//   - 参考: Go の net/http パッケージ (https://golang.org/pkg/net/http/)、RFC 5802 (https://tools.ietf.org/html/rfc5802)

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	iterationCount = 4096
)

var (
	// ハードコードされた認証情報（デモ用）。
	// 実際の運用では安全な方法でユーザーデータを管理してください。
	hardcodedUser     = "user"
	hardcodedPassword = "pencil"
	// sessions はクライアントの nonce をキーとしてセッション情報を管理します。
	sessions = map[string]*Session{}
)

// Session は SCRAM 認証に必要なセッション情報を保持する構造体です。
type Session struct {
	ClientNonce    string // クライアントから送信された nonce
	ServerNonce    string // サーバーが生成する nonce
	Salt           string // PBKDF2 に使用する salt（Base64 エンコード済み）
	Iteration      int    // PBKDF2 の反復回数
	StoredKey      []byte // クライアント証明検証用に計算されたキー
	ServerKey      []byte // サーバー署名用に計算されたキー
	ClientFirstMsg string // クライアントの初回メッセージ（"client-first bare"）
	ServerFirstMsg string // サーバー初回レスポンスメッセージ
}

// ScramRequest はクライアントから送信される JSON リクエストの形式です。
type ScramRequest struct {
	Step    string `json:"step"`    // 認証ステップ ("client-first" または "client-final")
	Message string `json:"message"` // SCRAM メッセージの内容
}

// ScramResponse はサーバーから返される JSON レスポンスの形式です。
type ScramResponse struct {
	Message string `json:"message"`         // サーバーからのレスポンスメッセージ
	Error   string `json:"error,omitempty"` // エラーがある場合、その詳細
}

// createNonce はランダムな英数字の文字列 (nonce) を生成します。
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

// sha256Hash はデータに対して SHA256 ハッシュを計算します。
func sha256Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// xorBytes は 2 つのバイトスライス間で XOR 演算を行い、その結果を返します。
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

// scramHandler は "/scram" エンドポイントへの HTTP POST リクエストを処理します。
func scramHandler(w http.ResponseWriter, r *http.Request) {
	// POST メソッド以外は拒否します。
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}

	// リクエストボディを読み込み、JSON をパースします。
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeResponse(w, ScramResponse{Error: "error reading body"})
		return
	}
	defer r.Body.Close()

	var req ScramRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeResponse(w, ScramResponse{Error: "invalid JSON"})
		return
	}

	// 認証ステップに応じて処理を分岐します。
	switch req.Step {
	case "client-first":
		handleClientFirst(w, req.Message)
	case "client-final":
		handleClientFinal(w, req.Message)
	default:
		writeResponse(w, ScramResponse{Error: "unknown step"})
	}
}

// handleClientFirst は "client-first" メッセージを処理し、
// クライアントからの初回認証リクエストを受け取ります。
func handleClientFirst(w http.ResponseWriter, message string) {
	// 期待される形式: "n,,n=<username>,r=<clientnonce>"
	parts := strings.Split(message, ",")
	if len(parts) < 3 {
		writeResponse(w, ScramResponse{Error: "invalid client-first format"})
		return
	}

	var username, clientNonce string
	for _, part := range parts {
		if strings.HasPrefix(part, "n=") {
			username = strings.TrimPrefix(part, "n=")
		}
		if strings.HasPrefix(part, "r=") {
			clientNonce = strings.TrimPrefix(part, "r=")
		}
	}

	// ユーザー名とクライアントからの nonce の検証
	if username != hardcodedUser || clientNonce == "" {
		writeResponse(w, ScramResponse{Error: "invalid username or missing client nonce"})
		return
	}

	// "n,," を除いたクライアント初回メッセージ (client-first bare) を生成
	clientFirstBare := fmt.Sprintf("n=%s,r=%s", username, clientNonce)

	// サーバー側の nonce と salt の生成
	serverNonce := createNonce(16)
	saltBytes := make([]byte, 16)
	rand.Read(saltBytes)
	salt := base64.StdEncoding.EncodeToString(saltBytes)

	// PBKDF2 を用いて salted password を生成
	saltedPassword := pbkdf2.Key([]byte(hardcodedPassword), saltBytes, iterationCount, 32, sha256.New)
	clientKey := hmacSha256(saltedPassword, "Client Key")
	storedKey := sha256Hash(clientKey)
	serverKey := hmacSha256(saltedPassword, "Server Key")

	// サーバー初回メッセージの形式: "r=<clientnonce><servernonce>,s=<salt>,i=<iterationCount>"
	combinedNonce := clientNonce + serverNonce
	serverFirstMsg := fmt.Sprintf("r=%s,s=%s,i=%d", combinedNonce, salt, iterationCount)

	// セッション情報を保存
	session := &Session{
		ClientNonce:    clientNonce,
		ServerNonce:    serverNonce,
		Salt:           salt,
		Iteration:      iterationCount,
		StoredKey:      storedKey,
		ServerKey:      serverKey,
		ClientFirstMsg: clientFirstBare,
		ServerFirstMsg: serverFirstMsg,
	}
	sessions[clientNonce] = session

	// サーバー初回メッセージをクライアントに返送
	writeResponse(w, ScramResponse{Message: serverFirstMsg})
}

// handleClientFinal は "client-final" メッセージを処理し、
// クライアント証明値を検証した上でサーバー署名を返します。
func handleClientFinal(w http.ResponseWriter, message string) {
	// 期待される形式: "c=<base64>,r=<combinednonce>,p=<clientproof>"
	parts := strings.Split(message, ",")
	if len(parts) < 3 {
		writeResponse(w, ScramResponse{Error: "invalid client-final format"})
		return
	}

	var combinedNonce, clientProofB64 string
	var clientFinalWithoutProof string
	for _, part := range parts {
		if strings.HasPrefix(part, "r=") {
			combinedNonce = strings.TrimPrefix(part, "r=")
		} else if strings.HasPrefix(part, "p=") {
			clientProofB64 = strings.TrimPrefix(part, "p=")
		}
	}

	if combinedNonce == "" || clientProofB64 == "" {
		writeResponse(w, ScramResponse{Error: "missing fields in client-final"})
		return
	}

	// クライアント nonce は combinedNonce の先頭部分（サーバー nonce は固定長 16 文字）
	clientNonce := combinedNonce[:len(combinedNonce)-16]
	session, ok := sessions[clientNonce]
	if !ok {
		writeResponse(w, ScramResponse{Error: "session not found"})
		return
	}

	// client-final メッセージから証明値部分 (",p=" 以降) を除去
	idx := strings.LastIndex(message, ",p=")
	if idx < 0 {
		writeResponse(w, ScramResponse{Error: "invalid client-final structure"})
		return
	}
	clientFinalWithoutProof = message[:idx]

	// 認証メッセージの再構築: client-first-bare, server-first-message, client-final-without-proof
	authMessage := fmt.Sprintf("%s,%s,%s", session.ClientFirstMsg, session.ServerFirstMsg, clientFinalWithoutProof)

	// クライアント証明値の検証プロセス
	clientProof, err := base64.StdEncoding.DecodeString(clientProofB64)
	if err != nil {
		writeResponse(w, ScramResponse{Error: "invalid base64 in client proof"})
		return
	}

	// クライアント署名の計算およびクライアントキーの復元
	clientSignature := hmacSha256(session.StoredKey, authMessage)
	recoveredClientKey := xorBytes(clientProof, clientSignature)
	storedKeyCandidate := sha256Hash(recoveredClientKey)

	// 復元したキーとセッションに保存された StoredKey の一致を検証
	if !hmac.Equal(storedKeyCandidate, session.StoredKey) {
		writeResponse(w, ScramResponse{Error: "authentication failed"})
		return
	}

	// 認証が成功した場合、サーバー署名を生成してクライアントに返送
	serverSignature := hmacSha256(session.ServerKey, authMessage)
	serverSignatureB64 := base64.StdEncoding.EncodeToString(serverSignature)

	// 使い終わったセッション情報の削除
	delete(sessions, session.ClientNonce)

	finalMsg := fmt.Sprintf("v=%s", serverSignatureB64)
	writeResponse(w, ScramResponse{Message: finalMsg})
}

// writeResponse は ScramResponse を JSON 形式にシリアライズしてクライアントに返送します。
func writeResponse(w http.ResponseWriter, resp ScramResponse) {
	w.Header().Set("Content-Type", "application/json")
	j, _ := json.Marshal(resp)
	fmt.Fprint(w, string(j))
}

// main 関数は、HTTP サーバーを起動し、"/scram" エンドポイントに scramHandler を登録します。
func main() {
	// 【説明】この main 関数は SCRAM-SHA256 認証サーバーのエントリーポイントです。
	// ハンドラーを "/scram" に登録し、ポート 8080 で HTTP サーバーを起動します。
	// 参考資料:
	//   - Go net/http パッケージ: https://golang.org/pkg/net/http/
	//   - RFC 5802: https://tools.ietf.org/html/rfc5802
	http.HandleFunc("/scram", scramHandler)

	fmt.Println("SCRAM-SHA256 server running on port 8080")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}
