package main

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed index.html
var htmlFS embed.FS

var htmlContent string
var dbMu sync.Mutex

func init() {
	data, err := htmlFS.ReadFile("index.html")
	if err == nil {
		htmlContent = string(data)
	}
}

// ============================================================
// #1  Constants
// ============================================================

const (
	CORE_KEY = "hzHRAmso5kInbaxW"
	META_KEY = "#14ljk_!\\]&0U<'("
	NCM_MAGIC = "CTENFDAM"

	maxKeyBlobLen  = 256 * 1024
	maxMetaBlobLen = 512 * 1024
	maxCoverLen    = 20 * 1024 * 1024
	bufferSize     = 64 * 1024

	// Mode constants
	MODE_LOCAL  = 0
	MODE_SERVER = 1

	// Config
	configFileName = "ncm-decrypt.json"
)

// configStore persists app configuration across restarts.
type configStore struct {
	Mode int `json:"mode"`
}

func configDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		if home != "" {
			return home
		}
		return "."
	}
	return filepath.Join(dir, "ncm-decrypt")
}

func loadSavedMode() int {
	path := filepath.Join(configDir(), configFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	var cfg configStore
	if json.Unmarshal(data, &cfg) != nil {
		return -1
	}
	if cfg.Mode != MODE_LOCAL && cfg.Mode != MODE_SERVER {
		return -1
	}
	return cfg.Mode
}

func saveMode(mode int) {
	dir := configDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	path := filepath.Join(dir, configFileName)
	cfg := configStore{Mode: mode}
	data, _ := json.Marshal(cfg)
	os.WriteFile(path, data, 0644)
}

// ============================================================
// Security: Path traversal prevention & input validation
// ============================================================

// safeJoin joins baseDir and userPath, then verifies the result stays within baseDir.
// This prevents path traversal attacks ("../", absolute paths, symlink escapes).
func safeJoin(baseDir, userPath string) (string, error) {
	// Reject empty paths
	if userPath == "" {
		return "", errors.New("path is empty")
	}
	// Reject absolute paths
	if filepath.IsAbs(userPath) {
		return "", errors.New("absolute paths not allowed")
	}
	// Reject explicit path traversal
	cleaned := filepath.Clean(userPath)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", errors.New("path traversal not allowed")
	}
	// Also reject if userPath itself contains ".." before cleaning
	if strings.Contains(userPath, "..") {
		return "", errors.New("path traversal not allowed")
	}
	// Join with base and clean
	joined := filepath.Join(baseDir, userPath)
	joined = filepath.Clean(joined)
	// Verify the result is within baseDir
	baseCleaned := filepath.Clean(baseDir)
	if !strings.HasPrefix(joined, baseCleaned+string(filepath.Separator)) && joined != baseCleaned {
		return "", errors.New("path escape detected")
	}
	return joined, nil
}

// validateUsername ensures usernames contain only safe characters (no path separators, no special chars).
func validateUsername(name string) error {
	if len(name) < 3 || len(name) > 32 {
		return errors.New("username must be 3-32 characters")
	}
	// Only allow letters, digits, underscore, hyphen, dot
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '_' || c == '-' || c == '.':
		default:
			return errors.New("username contains invalid characters (only A-Z, a-z, 0-9, _, -, . allowed)")
		}
	}
	return nil
}

// ============================================================
// i18n: Multi-language support
// ============================================================

type localeMap map[string]string

var translations = map[string]localeMap{
	"en": {
		"lang_name":               "English",
		"app_title":               "NCM Decrypt",
		"login_title":             "Please login to continue",
		"login_tab":               "Login",
		"register_tab":            "Register",
		"username":                "Username",
		"password":                "Password",
		"login_btn":               "Login",
		"register_btn":            "Register",
		"logout":                  "Logout",
		"upload_btn":              "Select .ncm files",
		"upload_hint":             "Upload files to your personal space",
		"upload_hint_local":       "or copy files to the data directory and refresh",
		"refresh":                 "Refresh",
		"decrypt_selected":        "Decrypt selected",
		"delete_source":           "Delete source",
		"dedup":                   "Dedup",
		"select_all":              "Select all",
		"deselect_all":            "Deselect all",
		"file_count":              "Files",
		"decrypted_count":         "Decrypted",
		"duplicate_count":         "Duplicates",
		"settings":                "Settings",
		"auto_clean":              "Auto-delete source after decrypt",
		"no_files":                "No .ncm files found",
		"upload_or_copy":          "Upload .ncm files or copy them to your data directory",
		"processing":              "Progress",
		"decrypted_files":         "Decrypted files",
		"new_folder":              "New Folder",
		"delete":                  "Delete",
		"rename":                  "Rename",
		"download":                "Download",
		"name":                    "Name",
		"size":                    "Size",
		"status":                  "Status",
		"status_decrypted":        "Decrypted",
		"status_pending":          "Pending",
		"status_waiting":          "Waiting",
		"status_completed":        "Completed",
		"status_error":            "Error",
		"confirm_delete":          "Are you sure you want to delete this?",
		"confirm_clean":           "Are you sure you want to delete all decrypted source files? This cannot be undone!",
		"folder_name":             "Folder name",
		"rename_to":               "Rename to",
		"cancel":                  "Cancel",
		"confirm":                 "Confirm",
		"back":                    "Back",
		"language":                "Language",
		"decrypt_all":             "Decrypt All",
		"data_dir":                "Data directory",
		"output_dir":              "Output directory",
		"unauthorized":            "Please login first",
		"login_success":           "Login successful",
		"register_success":        "Registration successful! Please login",
		"logout_success":          "Logged out",
		"upload_success":          "Files added",
		"upload_failed":           "Upload failed",
		"delete_success":          "Deleted",
		"delete_failed":           "Delete failed",
		"mkdir_success":           "Folder created",
		"mkdir_failed":            "Failed to create folder",
		"rename_success":          "Renamed successfully",
		"rename_failed":           "Rename failed",
		"load_failed":             "Failed to load file list",
		"decrypt_start_failed":    "Failed to start decryption",
		"confirm_red Decrypt":     "Selected files include already decrypted files. Re-decrypt all?",
		"only_decrypt_new":        "OK = re-decrypt all, Cancel = only new files",
		"path_updated":            "Directory updated",
		"settings_updated":        "Settings updated",
	},
	"zh-CN": {
		"lang_name":               "中文（简体）",
		"app_title":               "NCM Decrypt",
		"login_title":             "请登录以使用",
		"login_tab":               "登录",
		"register_tab":            "注册",
		"username":                "用户名",
		"password":                "密码",
		"login_btn":               "登录",
		"register_btn":            "注册",
		"logout":                  "退出",
		"upload_btn":              "选择 .ncm 文件",
		"upload_hint":             "上传文件到你的个人空间",
		"upload_hint_local":       "或复制文件到数据目录后点刷新",
		"refresh":                 "刷新",
		"decrypt_selected":        "解密选中",
		"delete_source":           "删源文件",
		"dedup":                   "去重",
		"select_all":              "全选",
		"deselect_all":            "取消",
		"file_count":              "文件",
		"decrypted_count":         "已解密",
		"duplicate_count":         "重复",
		"settings":                "设置",
		"auto_clean":              "解密后自动删除源文件",
		"no_files":                "没有找到 .ncm 文件",
		"upload_or_copy":          "上传 .ncm 文件或复制到数据目录",
		"processing":              "处理进度",
		"decrypted_files":         "已解密的文件",
		"new_folder":              "新建文件夹",
		"delete":                  "删除",
		"rename":                  "重命名",
		"download":                "下载",
		"name":                    "名称",
		"size":                    "大小",
		"status":                  "状态",
		"status_decrypted":        "已解密",
		"status_pending":          "待处理",
		"status_waiting":          "等待中",
		"status_completed":        "已完成",
		"status_error":            "失败",
		"confirm_delete":          "确定要删除吗？",
		"confirm_clean":           "确定删除已解密对应的 .ncm 源文件？此操作不可恢复！",
		"folder_name":             "文件夹名称",
		"rename_to":               "重命名为",
		"cancel":                  "取消",
		"confirm":                 "确定",
		"back":                    "返回",
		"language":                "语言",
		"decrypt_all":             "全部解密",
		"data_dir":                "数据目录",
		"output_dir":              "输出目录",
		"unauthorized":            "请先登录",
		"login_success":           "登录成功",
		"register_success":        "注册成功，请登录",
		"logout_success":          "已退出",
		"upload_success":          "文件已添加",
		"upload_failed":           "上传失败",
		"delete_success":          "已删除",
		"delete_failed":           "删除失败",
		"mkdir_success":           "文件夹已创建",
		"mkdir_failed":            "创建文件夹失败",
		"rename_success":          "重命名成功",
		"rename_failed":           "重命名失败",
		"load_failed":             "加载文件列表失败",
		"decrypt_start_failed":    "启动解密失败",
		"confirm_red Decrypt":     "已选文件中包含已解密过的文件",
		"only_decrypt_new":        "确定=全部重新解密，取消=只解密新文件",
		"path_updated":            "目录已更新",
		"settings_updated":        "设置已更新",
	},
	"zh-TW": {
		"lang_name":               "中文（繁體）",
		"app_title":               "NCM Decrypt",
		"login_title":             "請登入以使用",
		"login_tab":               "登入",
		"register_tab":            "註冊",
		"username":                "使用者名稱",
		"password":                "密碼",
		"login_btn":               "登入",
		"register_btn":            "註冊",
		"logout":                  "登出",
		"upload_btn":              "選擇 .ncm 檔案",
		"upload_hint":             "上傳檔案到你的個人空間",
		"upload_hint_local":       "或複製檔案到資料目錄後重新整理",
		"refresh":                 "重新整理",
		"decrypt_selected":        "解密選中",
		"delete_source":           "刪除來源檔",
		"dedup":                   "去重",
		"select_all":              "全選",
		"deselect_all":            "取消",
		"file_count":              "檔案",
		"decrypted_count":         "已解密",
		"duplicate_count":         "重複",
		"settings":                "設定",
		"auto_clean":              "解密後自動刪除來源檔",
		"no_files":                "沒有找到 .ncm 檔案",
		"upload_or_copy":          "上傳 .ncm 檔案或複製到資料目錄",
		"processing":              "處理進度",
		"decrypted_files":         "已解密的檔案",
		"new_folder":              "新建資料夾",
		"delete":                  "刪除",
		"rename":                  "重新命名",
		"download":                "下載",
		"name":                    "名稱",
		"size":                    "大小",
		"status":                  "狀態",
		"status_decrypted":        "已解密",
		"status_pending":          "待處理",
		"status_waiting":          "等待中",
		"status_completed":        "已完成",
		"status_error":            "失敗",
		"confirm_delete":          "確定要刪除嗎？",
		"confirm_clean":           "確定刪除已解密對應的 .ncm 原始檔案？此操作不可復原！",
		"folder_name":             "資料夾名稱",
		"rename_to":               "重新命名為",
		"cancel":                  "取消",
		"confirm":                 "確定",
		"back":                    "返回",
		"language":                "語言",
		"decrypt_all":             "全部解密",
		"data_dir":                "資料目錄",
		"output_dir":              "輸出目錄",
		"unauthorized":            "請先登入",
		"login_success":           "登入成功",
		"register_success":        "註冊成功，請登入",
		"logout_success":          "已登出",
		"upload_success":          "檔案已添加",
		"upload_failed":           "上傳失敗",
		"delete_success":          "已刪除",
		"delete_failed":           "刪除失敗",
		"mkdir_success":           "資料夾已建立",
		"mkdir_failed":            "建立資料夾失敗",
		"rename_success":          "重新命名成功",
		"rename_failed":           "重新命名失敗",
		"load_failed":             "載入檔案列表失敗",
		"decrypt_start_failed":    "啟動解密失敗",
		"confirm_red Decrypt":     "已選檔案中包含已解密過的檔案",
		"only_decrypt_new":        "確定=全部重新解密，取消=只解密新檔案",
		"path_updated":            "目錄已更新",
		"settings_updated":        "設定已更新",
	},
	"ko": {
		"lang_name":               "한국어",
		"app_title":               "NCM Decrypt",
		"login_title":             "계속하려면 로그인하세요",
		"login_tab":               "로그인",
		"register_tab":            "회원가입",
		"username":                "사용자명",
		"password":                "비밀번호",
		"login_btn":               "로그인",
		"register_btn":            "회원가입",
		"logout":                  "로그아웃",
		"upload_btn":              ".ncm 파일 선택",
		"upload_hint":             "개인 공간에 파일 업로드",
		"upload_hint_local":       "또는 데이터 디렉토리에 파일을 복사하고 새로고침",
		"refresh":                 "새로고침",
		"decrypt_selected":        "선택 복호화",
		"delete_source":           "원본 삭제",
		"dedup":                   "중복 제거",
		"select_all":              "전체 선택",
		"deselect_all":            "선택 해제",
		"file_count":              "파일",
		"decrypted_count":         "복호화됨",
		"duplicate_count":         "중복",
		"settings":                "설정",
		"auto_clean":              "복호화 후 원본 파일 자동 삭제",
		"no_files":                ".ncm 파일이 없습니다",
		"upload_or_copy":          ".ncm 파일을 업로드하거나 데이터 디렉토리에 복사하세요",
		"processing":              "처리 진행 상황",
		"decrypted_files":         "복호화된 파일",
		"new_folder":              "새 폴더",
		"delete":                  "삭제",
		"rename":                  "이름 변경",
		"download":                "다운로드",
		"name":                    "이름",
		"size":                    "크기",
		"status":                  "상태",
		"status_decrypted":        "복호화됨",
		"status_pending":          "대기 중",
		"status_waiting":          "대기 중",
		"status_completed":        "완료",
		"status_error":            "오류",
		"confirm_delete":          "삭제하시겠습니까?",
		"confirm_clean":           "복호화된 원본 .ncm 파일을 삭제하시겠습니까? 되돌릴 수 없습니다!",
		"folder_name":             "폴더 이름",
		"rename_to":               "새 이름",
		"cancel":                  "취소",
		"confirm":                 "확인",
		"back":                    "뒤로",
		"language":                "언어",
		"decrypt_all":             "전체 복호화",
		"data_dir":                "데이터 디렉토리",
		"output_dir":              "출력 디렉토리",
		"unauthorized":            "먼저 로그인해주세요",
		"login_success":           "로그인 성공",
		"register_success":        "회원가입 성공! 로그인해주세요",
		"logout_success":          "로그아웃되었습니다",
		"upload_success":          "파일이 추가되었습니다",
		"upload_failed":           "업로드 실패",
		"delete_success":          "삭제되었습니다",
		"delete_failed":           "삭제 실패",
		"mkdir_success":           "폴더가 생성되었습니다",
		"mkdir_failed":            "폴더 생성 실패",
		"rename_success":          "이름이 변경되었습니다",
		"rename_failed":           "이름 변경 실패",
		"load_failed":             "파일 목록을 불러오지 못했습니다",
		"decrypt_start_failed":    "복호화를 시작하지 못했습니다",
		"confirm_red Decrypt":     "선택한 파일에 이미 복호화된 파일이 포함되어 있습니다",
		"only_decrypt_new":        "확인=전체 재복호화, 취소=새 파일만",
		"path_updated":            "디렉토리가 업데이트되었습니다",
		"settings_updated":        "설정이 업데이트되었습니다",
	},
	"ja": {
		"lang_name":               "日本語",
		"app_title":               "NCM Decrypt",
		"login_title":             "続行するにはログインしてください",
		"login_tab":               "ログイン",
		"register_tab":            "登録",
		"username":                "ユーザー名",
		"password":                "パスワード",
		"login_btn":               "ログイン",
		"register_btn":            "登録",
		"logout":                  "ログアウト",
		"upload_btn":              ".ncm ファイルを選択",
		"upload_hint":             "個人スペースにファイルをアップロード",
		"upload_hint_local":       "またはデータディレクトリにファイルをコピーして更新",
		"refresh":                 "更新",
		"decrypt_selected":        "選択を復号",
		"delete_source":           "元ファイルを削除",
		"dedup":                   "重複排除",
		"select_all":              "すべて選択",
		"deselect_all":            "選択解除",
		"file_count":              "ファイル",
		"decrypted_count":         "復号済み",
		"duplicate_count":         "重複",
		"settings":                "設定",
		"auto_clean":              "復号後に元ファイルを自動削除",
		"no_files":                ".ncm ファイルが見つかりません",
		"upload_or_copy":          ".ncm ファイルをアップロードするか、データディレクトリにコピーしてください",
		"processing":              "処理状況",
		"decrypted_files":         "復号済みファイル",
		"new_folder":              "新しいフォルダ",
		"delete":                  "削除",
		"rename":                  "名前変更",
		"download":                "ダウンロード",
		"name":                    "名前",
		"size":                    "サイズ",
		"status":                  "状態",
		"status_decrypted":        "復号済み",
		"status_pending":          "待機中",
		"status_waiting":          "待機中",
		"status_completed":        "完了",
		"status_error":            "エラー",
		"confirm_delete":          "削除してもよろしいですか？",
		"confirm_clean":           "復号済みの元 .ncm ファイルを削除してもよろしいですか？この操作は元に戻せません！",
		"folder_name":             "フォルダ名",
		"rename_to":               "新しい名前",
		"cancel":                  "キャンセル",
		"confirm":                 "確認",
		"back":                    "戻る",
		"language":                "言語",
		"decrypt_all":             "すべて復号",
		"data_dir":                "データディレクトリ",
		"output_dir":              "出力ディレクトリ",
		"unauthorized":            "ログインしてください",
		"login_success":           "ログイン成功",
		"register_success":        "登録成功！ログインしてください",
		"logout_success":          "ログアウトしました",
		"upload_success":          "ファイルが追加されました",
		"upload_failed":           "アップロード失敗",
		"delete_success":          "削除しました",
		"delete_failed":           "削除失敗",
		"mkdir_success":           "フォルダを作成しました",
		"mkdir_failed":            "フォルダ作成失敗",
		"rename_success":          "名前を変更しました",
		"rename_failed":           "名前変更失敗",
		"load_failed":             "ファイル一覧の読み込みに失敗しました",
		"decrypt_start_failed":    "復号の開始に失敗しました",
		"confirm_red Decrypt":     "選択したファイルに復号済みのものが含まれています",
		"only_decrypt_new":        "OK=すべて再復号、キャンセル=新規のみ",
		"path_updated":            "ディレクトリを更新しました",
		"settings_updated":        "設定を更新しました",
	},
}

var supportedLocales = []string{"en", "zh-CN", "zh-TW", "ko", "ja"}

// detectLocale determines the best matching locale from Accept-Language header.
func detectLocale(acceptLang string) string {
	if acceptLang == "" {
		return "en"
	}
	// Parse Accept-Language header, respecting quality values
	type langQ struct {
		lang string
		q    float64
	}
	var parsed []langQ
	for _, part := range strings.Split(acceptLang, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		q := 1.0
		if idx := strings.Index(part, ";"); idx >= 0 {
			fmt.Sscanf(part[idx:], ";q=%f", &q)
			part = part[:idx]
		}
		parsed = append(parsed, langQ{lang: strings.TrimSpace(part), q: q})
	}
	// Sort by quality descending
	sort.Slice(parsed, func(i, j int) bool { return parsed[i].q > parsed[j].q })

	// Try to match against supported locales
	for _, p := range parsed {
		lang := p.lang
		for _, supported := range supportedLocales {
			if strings.EqualFold(lang, supported) {
				return supported
			}
		}
		// Try matching language part only (e.g. "zh" -> "zh-CN")
		langBase := strings.Split(lang, "-")[0]
		for _, supported := range supportedLocales {
			if strings.EqualFold(langBase, strings.Split(supported, "-")[0]) {
				return supported
			}
		}
	}
	return "en"
}

// t returns the translated string for a key in the given locale, falling back to English.
func t(locale, key string) string {
	if m, ok := translations[locale]; ok {
		if s, ok := m[key]; ok {
			return s
		}
	}
	// Fallback to English
	if s, ok := translations["en"][key]; ok {
		return s
	}
	return key
}

// ============================================================
// #2  AES-128-ECB
// ============================================================

func aesECBDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("aes: ciphertext not multiple of block size")
	}
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(plaintext[i:i+aes.BlockSize], ciphertext[i:i+aes.BlockSize])
	}
	padLen := int(plaintext[len(plaintext)-1])
	if padLen == 0 || padLen > aes.BlockSize {
		return nil, errors.New("aes: invalid PKCS#7 padding")
	}
	for _, b := range plaintext[len(plaintext)-padLen:] {
		if b != byte(padLen) {
			return nil, errors.New("aes: invalid padding byte")
		}
	}
	return plaintext[:len(plaintext)-padLen], nil
}

// ============================================================
// #3  NCM RC4 (stateless per-offset PRGA)
// ============================================================

type ncmRC4 struct {
	s [256]byte
}

func newNCMRC4(key []byte) *ncmRC4 {
	var c ncmRC4
	for i := range c.s {
		c.s[i] = byte(i)
	}
	var j byte
	for i := range c.s {
		j += c.s[byte(i)] + key[i%len(key)]
		c.s[byte(i)], c.s[j] = c.s[j], c.s[byte(i)]
	}
	return &c
}

func (c *ncmRC4) decrypt(buf []byte, baseOffset int64) {
	s := c.s
	for k := 0; k < len(buf); k++ {
		off := baseOffset + int64(k)
		j := byte((off + 1) & 0xFF)
		a := s[j]
		b := s[(int(a)+int(j))%256]
		ks := s[(int(a)+int(b))%256]
		buf[k] ^= ks
	}
}

// ============================================================
// #4  NCM Header Parser
// ============================================================

type ncmHeader struct {
	keyBlob    []byte
	metaBlob   []byte
	coverData  []byte
	audioOffset int64
	audioLen   int64
}

func parseNCMHeader(r io.ReadSeeker) (*ncmHeader, error) {
	h := &ncmHeader{}

	// Magic
	var magic [8]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, fmt.Errorf("ncm: read magic: %w", err)
	}
	if string(magic[:]) != NCM_MAGIC {
		return nil, errors.New("ncm: invalid magic, not an NCM file")
	}

	// Skip 2-byte gap
	if _, err := r.Seek(2, io.SeekCurrent); err != nil {
		return nil, fmt.Errorf("ncm: skip gap: %w", err)
	}

	// RC4 key blob
	var keyLen uint32
	if err := binary.Read(r, binary.LittleEndian, &keyLen); err != nil {
		return nil, fmt.Errorf("ncm: read key length: %w", err)
	}
	if keyLen == 0 || keyLen > maxKeyBlobLen {
		return nil, fmt.Errorf("ncm: invalid key length %d", keyLen)
	}
	h.keyBlob = make([]byte, keyLen)
	if _, err := io.ReadFull(r, h.keyBlob); err != nil {
		return nil, fmt.Errorf("ncm: read key blob: %w", err)
	}

	// Meta blob
	var metaLen uint32
	if err := binary.Read(r, binary.LittleEndian, &metaLen); err != nil {
		return nil, fmt.Errorf("ncm: read meta length: %w", err)
	}
	if metaLen > maxMetaBlobLen {
		return nil, fmt.Errorf("ncm: invalid meta length %d", metaLen)
	}
	if metaLen > 0 {
		h.metaBlob = make([]byte, metaLen)
		if _, err := io.ReadFull(r, h.metaBlob); err != nil {
			return nil, fmt.Errorf("ncm: read meta blob: %w", err)
		}
	}

	// Skip CRC32 (4) + gap (5) = 9 bytes
	if _, err := r.Seek(9, io.SeekCurrent); err != nil {
		return nil, fmt.Errorf("ncm: skip crc+gap: %w", err)
	}

	// Cover image
	var coverLen uint32
	if err := binary.Read(r, binary.LittleEndian, &coverLen); err != nil {
		return nil, fmt.Errorf("ncm: read cover length: %w", err)
	}
	if coverLen > maxCoverLen {
		return nil, fmt.Errorf("ncm: invalid cover length %d", coverLen)
	}
	if coverLen > 0 {
		h.coverData = make([]byte, coverLen)
		if _, err := io.ReadFull(r, h.coverData); err != nil {
			return nil, fmt.Errorf("ncm: read cover data: %w", err)
		}
	}

	// Audio offset
	off, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("ncm: seek audio: %w", err)
	}
	h.audioOffset = off
	if s, ok := r.(interface{ Size() int64 }); ok {
		h.audioLen = s.Size() - off
	}
	return h, nil
}

// ============================================================
// #5  KDF (Key Derivation)
// ============================================================

func deriveRC4Key(blob []byte) ([]byte, error) {
	if len(blob) > maxKeyBlobLen || len(blob) < 17 {
		return nil, errors.New("kdf: invalid blob size")
	}
	xored := make([]byte, len(blob))
	for i, b := range blob {
		xored[i] = b ^ 0x64
	}
	decrypted, err := aesECBDecrypt([]byte(CORE_KEY), xored)
	if err != nil {
		return nil, fmt.Errorf("kdf: %w", err)
	}
	const prefix = "neteasecloudmusic"
	if len(decrypted) < len(prefix) || string(decrypted[:len(prefix)]) != prefix {
		return nil, errors.New("kdf: missing prefix")
	}
	key := decrypted[len(prefix):]
	if len(key) == 0 {
		return nil, errors.New("kdf: empty key")
	}
	return key, nil
}

func decryptMeta(blob []byte) ([]byte, error) {
	if len(blob) > maxMetaBlobLen || len(blob) < 22 {
		return nil, errors.New("kdf: invalid meta blob size")
	}
	xored := make([]byte, len(blob))
	for i, b := range blob {
		xored[i] = b ^ 0x63
	}
	const prefix = "163 key(Don't modify):"
	payload := string(xored)
	if !strings.HasPrefix(payload, prefix) {
		return nil, errors.New("kdf: meta missing prefix")
	}
	payload = payload[len(prefix):]

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("kdf: base64: %w", err)
	}
	decrypted, err := aesECBDecrypt([]byte(META_KEY), decoded)
	if err != nil {
		return nil, fmt.Errorf("kdf: aes meta: %w", err)
	}
	const mp = "music:"
	if len(decrypted) < len(mp) || string(decrypted[:len(mp)]) != mp {
		return nil, errors.New("kdf: meta missing music: prefix")
	}
	jsonBytes := decrypted[len(mp):]
	if len(jsonBytes) == 0 {
		return nil, errors.New("kdf: empty meta JSON")
	}
	return jsonBytes, nil
}

// ============================================================
// #6  Metadata & Format Detection
// ============================================================

type songMeta struct {
	MusicName string `json:"musicName"`
	Artist    string `json:"artist"`
	Album     string `json:"album"`
	Format    string `json:"format"`
	Bitrate   int    `json:"bitrate"`
	Duration  int    `json:"duration"`
	AlbumID   int64  `json:"albumId,omitempty"`
	MusicID   int64  `json:"musicId,omitempty"`
}

func parseSongMeta(jsonData []byte) *songMeta {
	var raw struct {
		MusicName string          `json:"musicName"`
		Artist    json.RawMessage `json:"artist"`
		Album     string          `json:"album"`
		Format    string          `json:"format"`
		Bitrate   int             `json:"bitrate"`
		Duration  int             `json:"duration"`
		AlbumID   int64           `json:"albumId,omitempty"`
		MusicID   int64           `json:"musicId,omitempty"`
	}
	if err := json.Unmarshal(jsonData, &raw); err != nil {
		return nil
	}
	m := &songMeta{
		MusicName: raw.MusicName,
		Album:     raw.Album,
		Format:    raw.Format,
		Bitrate:   raw.Bitrate,
		Duration:  raw.Duration,
		AlbumID:   raw.AlbumID,
		MusicID:   raw.MusicID,
	}
	// Parse artist: could be simple string or nested array [["name", id], ...]
	if len(raw.Artist) > 0 {
		if raw.Artist[0] == '"' {
			json.Unmarshal(raw.Artist, &m.Artist)
		} else {
			var artists [][]interface{}
			if json.Unmarshal(raw.Artist, &artists) == nil && len(artists) > 0 && len(artists[0]) > 0 {
				if name, ok := artists[0][0].(string); ok {
					m.Artist = name
				}
			}
		}
	}
	return m
}

func (m *songMeta) displayName() string {
	if m == nil {
		return ""
	}
	if m.Artist != "" {
		return m.Artist + " - " + m.MusicName
	}
	return m.MusicName
}

func detectFormat(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	switch {
	case data[0] == 0xFF && (data[1]&0xE0) == 0xE0:
		return "mp3"
	case string(data[:3]) == "ID3":
		return "mp3"
	case string(data[:4]) == "fLaC":
		return "flac"
	case len(data) >= 8 && string(data[4:8]) == "ftyp":
		return "m4a"
	case string(data[:4]) == "RIFF":
		return "wav"
	case string(data[:4]) == "OggS":
		return "ogg"
	case string(data[:4]) == "FORM":
		return "aiff"
	case string(data[:4]) == "MAC " || string(data[:4]) == "mac ":
		return "ape"
	}
	// Scan for signatures at non-zero offsets
	limit := len(data)
	if limit > 128 {
		limit = 128
	}
	for i := 0; i < limit-3; i++ {
		b := data[i : i+4]
		if string(b) == "fLaC" {
			return "flac"
		}
		if string(b) == "OggS" {
			return "ogg"
		}
		if i < 16 && data[i] == 0xFF && (data[i+1]&0xE0) == 0xE0 {
			return "mp3"
		}
		if i < 3 && string(b[:3]) == "ID3" {
			return "mp3"
		}
		if i < 32 && string(b) == "ftyp" {
			return "m4a"
		}
	}
	return ""
}

func extFor(format string) string {
	switch format {
	case "mp3", "flac", "m4a", "wav", "ogg", "aiff", "ape":
		return "." + format
	}
	return ".audio"
}

// ============================================================
// #7  Decrypt Engine
// ============================================================

type decryptResult struct {
	meta       *songMeta
	coverData  []byte
	outputPath string
	format     string
	sizeBytes  int64
}

func decryptFile(inputPath, outputDir string) (*decryptResult, error) {
	f, err := os.Open(inputPath)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	// Parse header
	header, err := parseNCMHeader(f)
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}

	// Derive RC4 key
	rc4Key, err := deriveRC4Key(header.keyBlob)
	if err != nil {
		return nil, fmt.Errorf("kdf: %w", err)
	}

	// Decrypt metadata
	var m *songMeta
	if len(header.metaBlob) > 0 {
		jsonBytes, err := decryptMeta(header.metaBlob)
		if err == nil {
			m = parseSongMeta(jsonBytes)
		}
	}

	// Sample audio to detect format
	rc4 := newNCMRC4(rc4Key)
	sampler := make([]byte, 4096)
	if _, err := io.ReadFull(f, sampler); err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("sample: %w", err)
	}
	rc4.decrypt(sampler, 0)
	format := detectFormat(sampler)
	if format == "" {
		n := 16
		if len(sampler) < n {
			n = len(sampler)
		}
		log.Printf("  [%s] unknown audio format, bytes: % x", filepath.Base(inputPath), sampler[:n])
		format = "audio"
	}

	// Output path
	base := filepath.Base(inputPath)
	base = strings.TrimSuffix(base, ".ncm")
	if m != nil && m.MusicName != "" {
		name := m.displayName()
		if name != "" {
			base = sanitize(name)
		}
	}
	ext := extFor(format)
	outputPath := filepath.Join(outputDir, base+ext)

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	// Stream-decrypt audio with 64KB buffer
	tmpPath := outputPath + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("create: %w", err)
	}
	defer out.Close()

	// Seek back to audio start
	if _, err := f.Seek(header.audioOffset, io.SeekStart); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("seek: %w", err)
	}

	rc4Stream := newNCMRC4(rc4Key)
	buf := make([]byte, bufferSize)
	var total int64
	audioSize := header.audioLen

	for {
		nr, err := f.Read(buf)
		if nr > 0 {
			chunk := buf[:nr]
			rc4Stream.decrypt(chunk, total)
			if _, werr := out.Write(chunk); werr != nil {
				os.Remove(tmpPath)
				return nil, fmt.Errorf("write: %w", werr)
			}
			total += int64(nr)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			os.Remove(tmpPath)
			return nil, fmt.Errorf("read: %w", err)
		}
		_ = audioSize
	}

	if err := out.Close(); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpPath, outputPath); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("rename: %w", err)
	}

	// Write metadata tags and cover art
	if m != nil || len(header.coverData) > 0 {
		if err := writeAudioTags(outputPath, m, header.coverData, format); err != nil {
			log.Printf("  tag warning: %v", err)
		}
	}

	return &decryptResult{
		meta:       m,
		coverData:  header.coverData,
		outputPath: outputPath,
		format:     format,
		sizeBytes:  total,
	}, nil
}


// writeAudioTags writes metadata (title, artist, album) and cover art to the decoded audio file.
func writeAudioTags(filePath string, meta *songMeta, coverData []byte, format string) error {
	switch format {
	case "mp3":
		return writeID3v2(filePath, meta, coverData)
	case "flac":
		return writeFLACMeta(filePath, meta, coverData)
	}
	return nil
}

func writeID3v2(filePath string, meta *songMeta, coverData []byte) error {
	if meta == nil && len(coverData) == 0 {
		return nil
	}
	// Build ID3v2.3 frames
	var frames []byte
	appendFrame := func(id string, data []byte) {
		frame := make([]byte, 10+len(data))
		copy(frame[0:4], id)
		binary.BigEndian.PutUint32(frame[4:8], uint32(len(data)))
		copy(frame[10:], data)
		frames = append(frames, frame...)
	}
	frameData := func(enc byte, s string) []byte {
		d := []byte{enc}
		d = append(d, []byte(s)...)
		return d
	}
	if meta != nil && meta.MusicName != "" {
		appendFrame("TIT2", frameData(3, meta.MusicName))
	}
	if meta != nil && meta.Artist != "" {
		appendFrame("TPE1", frameData(3, meta.Artist))
	}
	if meta != nil && meta.Album != "" {
		appendFrame("TALB", frameData(3, meta.Album))
	}
	if len(coverData) > 0 {
		mime := "image/jpeg"
		if len(coverData) >= 4 && coverData[0] == 0x89 && string(coverData[1:4]) == "PNG" {
			mime = "image/png"
		}
		apic := []byte{3} // encoding: UTF-8
		apic = append(apic, []byte(mime)...)
		apic = append(apic, 0) // null terminator for mime
		apic = append(apic, 3) // picture type: front cover
		apic = append(apic, 0) // description: empty (null terminated)
		apic = append(apic, coverData...)
		appendFrame("APIC", apic)
	}
	if len(frames) == 0 {
		return nil
	}
	// ID3v2 header: "ID3", 0x03, 0x00, flags, size (synchsafe)
	size := len(frames)
	syncSize := []byte{
		byte((size >> 21) & 0x7F),
		byte((size >> 14) & 0x7F),
		byte((size >> 7) & 0x7F),
		byte(size & 0x7F),
	}
	header := []byte("ID3")
	header = append(header, 3, 0, 0) // version 2.3, no flags
	header = append(header, syncSize...)
	header = append(header, frames...)

	// Prepend to file
	orig, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, append(header, orig...), 0644)
}

func writeFLACMeta(filePath string, meta *songMeta, coverData []byte) error {
	if meta == nil && len(coverData) == 0 {
		return nil
	}
	orig, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	if len(orig) < 42 || string(orig[:4]) != "fLaC" {
		return fmt.Errorf("not a valid FLAC file")
	}
	// Parse existing metadata blocks to find where audio data starts
	i := 4 // skip "fLaC"
	var metaBlocks [][]byte
	for i < len(orig) {
		if i+4 > len(orig) {
			break
		}
		isLast := (orig[i] & 0x80) != 0
		blockType := orig[i] & 0x7F
		blockLen := int(orig[i+1])<<16 | int(orig[i+2])<<8 | int(orig[i+3])
		i += 4
		if i+blockLen > len(orig) {
			break
		}
		block := orig[i : i+blockLen]
		i += blockLen
		metaBlocks = append(metaBlocks, append([]byte{blockType, byte(blockLen>>16), byte(blockLen>>8), byte(blockLen)}, block...))
		if isLast {
			break
		}
	}
	audioStart := i

	// Build Vorbis Comment block
	var vc []byte
	// Vendor string
	vendor := "ncm-decrypt"
	vendorLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(vendorLen, uint32(len(vendor)))
	vc = append(vc, vendorLen...)
	vc = append(vc, []byte(vendor)...)
	// Count comments
	var comments []byte
	if meta != nil && meta.MusicName != "" {
		c := "TITLE=" + meta.MusicName
		cl := make([]byte, 4)
		binary.LittleEndian.PutUint32(cl, uint32(len(c)))
		comments = append(comments, cl...)
		comments = append(comments, []byte(c)...)
	}
	if meta != nil && meta.Artist != "" {
		c := "ARTIST=" + meta.Artist
		cl := make([]byte, 4)
		binary.LittleEndian.PutUint32(cl, uint32(len(c)))
		comments = append(comments, cl...)
		comments = append(comments, []byte(c)...)
	}
	if meta != nil && meta.Album != "" {
		c := "ALBUM=" + meta.Album
		cl := make([]byte, 4)
		binary.LittleEndian.PutUint32(cl, uint32(len(c)))
		comments = append(comments, cl...)
		comments = append(comments, []byte(c)...)
	}
	numComments := make([]byte, 4)
	binary.LittleEndian.PutUint32(numComments, uint32(len(comments)/8)) // each comment is 4+len bytes
	vc = append(vc, numComments...)
	vc = append(vc, comments...)

	// Build Vorbis Comment block header (type 4)
	blen := len(vc)
	vcHeader := []byte{4, byte(blen >> 16), byte(blen >> 8), byte(blen)}

	// Build Picture block if cover art exists
	var picBlock []byte
	if len(coverData) > 0 {
		mime := "image/jpeg"
		if len(coverData) >= 4 && coverData[0] == 0x89 && string(coverData[1:4]) == "PNG" {
			mime = "image/png"
		}
		var pic []byte
		// Picture type (32-bit BE)
		pic = binary.BigEndian.AppendUint32(pic, 3) // front cover
		// MIME type (32-bit LE length + UTF-8)
		mimeLen := make([]byte, 4)
		binary.BigEndian.PutUint32(mimeLen, uint32(len(mime)))
		pic = append(pic, mimeLen...)
		pic = append(pic, []byte(mime)...)
		// Description (0 length == no description)
		pic = append(pic, 0, 0, 0, 0)
		// Width, Height, ColorDepth, ColorsUsed (32-bit BE each, 0 = unknown)
		pic = binary.BigEndian.AppendUint32(pic, 0) // width
		pic = binary.BigEndian.AppendUint32(pic, 0) // height
		pic = binary.BigEndian.AppendUint32(pic, 0) // color depth
		pic = binary.BigEndian.AppendUint32(pic, 0) // colors used
		// Picture data (32-bit LE length + bytes)
		picLen := make([]byte, 4)
		binary.BigEndian.PutUint32(picLen, uint32(len(coverData)))
		pic = append(pic, picLen...)
		pic = append(pic, coverData...)

		blen2 := len(pic)
		picBlock = append([]byte{6, byte(blen2 >> 16), byte(blen2 >> 8), byte(blen2)}, pic...)
	}

	// Rebuild FLAC file: "fLaC" + STREAMINFO + VORBIS_COMMENT + PICTURE(last) + audio
	var out []byte
	out = append(out, []byte("fLaC")...)
	// StreamInfo (keep original, set isLast=false)
	if len(metaBlocks) > 0 {
		streamInfo := metaBlocks[0]
		streamInfo[0] &^= 0x80 // clear isLast flag
		out = append(out, streamInfo...)
	}
	// Vorbis Comment (not last)
	out = append(out, vcHeader...)
	out = append(out, vc...)
	// Picture (set as last)
	if len(picBlock) > 0 {
		picBlock[0] |= 0x80 // set isLast flag
		out = append(out, picBlock...)
	} else {
		out[len(out)-1] |= 0x80 // no picture, make comment the last
	}
	// Audio data
	out = append(out, orig[audioStart:]...)

	return os.WriteFile(filePath, out, 0644)
}
func sanitize(name string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", " -",
		"*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	return strings.TrimSpace(r.Replace(name))
}

// ============================================================
// #8  Decryption Tracking DB
// ============================================================

type decryptEntry struct {
	FileName    string `json:"file_name"`
	SourceFile  string `json:"source_file"`
	DecryptedAt string `json:"decrypted_at"`
	OutputFile  string `json:"output_file"`
	Format      string `json:"format"`
	Size        int64  `json:"size"`
}

const dbFileName = ".decrypted.json"

func loadDecryptDB(dir string) map[string]decryptEntry {
	db := make(map[string]decryptEntry)
	data, err := os.ReadFile(filepath.Join(dir, dbFileName))
	if err != nil {
		return db
	}
	json.Unmarshal(data, &db) // ignore corrupted DB
	return db
}

func saveDecryptDB(dir string, db map[string]decryptEntry) {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(filepath.Join(dir, dbFileName), data, 0644)
}

func updateDecryptDB(dir string, fn func(db map[string]decryptEntry)) {
	dbMu.Lock()
	defer dbMu.Unlock()
	db := loadDecryptDB(dir)
	fn(db)
	saveDecryptDB(dir, db)
}

// ============================================================
// #9  User Authentication (Mode 1)
// ============================================================

type userEntry struct {
	PasswordHash string `json:"password_hash"`
	Salt         string `json:"salt"`
	CreatedAt    string `json:"created_at"`
}

type userStore struct {
	mu    sync.RWMutex
	path  string // path to users.json
	users map[string]userEntry
}

func newUserStore(serverDir string) *userStore {
	path := filepath.Join(serverDir, "users.json")
	us := &userStore{
		path:  path,
		users: make(map[string]userEntry),
	}
	// Load existing users
	data, err := os.ReadFile(path)
	if err == nil {
		json.Unmarshal(data, &us.users)
	}
	return us
}

func (us *userStore) save() {
	data, _ := json.MarshalIndent(us.users, "", "  ")
	os.WriteFile(us.path, data, 0644)
}

func (us *userStore) register(username, password string) error {
	us.mu.Lock()
	defer us.mu.Unlock()

	if err := validateUsername(username); err != nil {
		return err
	}
	if len(password) < 4 {
		return errors.New("password must be at least 4 characters")
	}
	if _, exists := us.users[username]; exists {
		return errors.New("username already exists")
	}

	salt := randomHex(16)
	hash := hashPassword(password, salt)

	us.users[username] = userEntry{
		PasswordHash: hash,
		Salt:         salt,
		CreatedAt:    time.Now().Format(time.RFC3339),
	}
	us.save()
	return nil
}

func (us *userStore) authenticate(username, password string) bool {
	us.mu.RLock()
	defer us.mu.RUnlock()

	entry, exists := us.users[username]
	if !exists {
		return false
	}
	return entry.PasswordHash == hashPassword(password, entry.Salt)
}

func (us *userStore) exists(username string) bool {
	us.mu.RLock()
	defer us.mu.RUnlock()
	_, ok := us.users[username]
	return ok
}

// sessionStore manages login sessions in memory
type sessionEntry struct {
	username  string
	createdAt time.Time
}

type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]sessionEntry
}

const sessionMaxAge = 7 * 24 * time.Hour

func newSessionStore() *sessionStore {
	ss := &sessionStore{
		sessions: make(map[string]sessionEntry),
	}
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			ss.cleanup()
		}
	}()
	return ss
}

func (ss *sessionStore) cleanup() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	now := time.Now()
	for token, entry := range ss.sessions {
		if now.Sub(entry.createdAt) > sessionMaxAge {
			delete(ss.sessions, token)
		}
	}
}

func (ss *sessionStore) create(username string) string {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	token := randomHex(32)
	ss.sessions[token] = sessionEntry{
		username:  username,
		createdAt: time.Now(),
	}
	return token
}

func (ss *sessionStore) getUsername(token string) (string, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	entry, ok := ss.sessions[token]
	if !ok {
		return "", false
	}
	if time.Since(entry.createdAt) > sessionMaxAge {
		return "", false
	}
	return entry.username, true
}

func (ss *sessionStore) remove(token string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.sessions, token)
}

func randomHex(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hashPassword(password, salt string) string {
	h := sha256.Sum256([]byte(salt + password))
	return hex.EncodeToString(h[:])
}

// extractUsernameFromPath extracts the username from a sandbox path like .../users/{username}/output
func extractUsernameFromPath(path string) string {
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	for i, p := range parts {
		if p == "users" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// ============================================================
// #10  Worker Pool
// ============================================================

type decryptTask struct {
	ID            string
	FilePath      string
	FileName      string
	Hash          string
	Size          int64
	IsUpload      bool   // auto-delete source after decrypt
	DBDir         string // directory for .decrypted.json
	TaskOutputDir string // overrides pool default output dir
	Username      string // for SSE user isolation
}

type decryptProgress struct {
	TaskID   string  `json:"task_id"`
	File     string  `json:"file"`
	Progress float64 `json:"progress"`
	State    string  `json:"state"`
	Error    string  `json:"error,omitempty"`
	Output   string  `json:"output,omitempty"`
	Format   string  `json:"format,omitempty"`
	Size     int64   `json:"size_bytes,omitempty"`
	Username string  `json:"username,omitempty"`
}

type workerPool struct {
	mu      sync.Mutex
	tasks   map[string]*decryptTask
	queue   chan string
	workers int
	output  string
	hub     *sseHub
	wg      sync.WaitGroup
	stopCh  chan struct{}
}

func newWorkerPool(workers int, output string, hub *sseHub) *workerPool {
	return &workerPool{
		tasks:   make(map[string]*decryptTask),
		queue:   make(chan string, 1000),
		workers: workers,
		output:  output,
		hub:     hub,
		stopCh:  make(chan struct{}),
	}
}

func (wp *workerPool) start() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.workerLoop()
	}
}


func (wp *workerPool) stop() {
	close(wp.stopCh)
	wp.wg.Wait()
}

func (wp *workerPool) setOutput(d string) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	wp.output = d
}


func (wp *workerPool) enqueue(filePath string, isUpload bool, dbDir string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	io.Copy(h, f)
	f.Close()
	hash := fmt.Sprintf("%x", h.Sum(nil))

	fi, _ := os.Stat(filePath)
	var size int64
	if fi != nil {
		size = fi.Size()
	}

	wp.mu.Lock()
	// Dedup by hash
	for _, t := range wp.tasks {
		if t.Hash == hash {
			wp.mu.Unlock()
			return t.ID, nil // already queued
		}
	}
	id := fmt.Sprintf("tsk_%04x", len(wp.tasks)+1)
	t := &decryptTask{
		ID:            id,
		FilePath:      filePath,
		FileName:      filepath.Base(filePath),
		Hash:          hash,
		Size:          size,
		IsUpload:      isUpload,
		DBDir:         dbDir,
		TaskOutputDir: dbDir, // default same as DB dir
		Username:      extractUsernameFromPath(dbDir),
	}
	wp.tasks[id] = t
	wp.mu.Unlock()

	select {
	case wp.queue <- id:
	case <-wp.stopCh:
		return "", errors.New("pool stopped")
	}
	return id, nil
}

func (wp *workerPool) workerLoop() {
	defer wp.wg.Done()
	for {
		select {
		case <-wp.stopCh:
			return
		case id := <-wp.queue:
			wp.mu.Lock()
			t := wp.tasks[id]
			wp.mu.Unlock()
			if t == nil {
				continue
			}

			wp.hub.send(decryptProgress{
				TaskID:   id,
				File:     t.FileName,
				Progress: 5,
				State:    "decrypting",
			})

			// Use per-task output dir if set, otherwise pool default
			outputDir := t.TaskOutputDir
			if outputDir == "" {
				outputDir = wp.output
			}

			result, err := decryptFile(t.FilePath, outputDir)
			if err != nil {
				wp.hub.send(decryptProgress{
					TaskID:   id,
					File:     t.FileName,
					Progress: 0,
					State:    "error",
					Error:    err.Error(),
				})
				continue
			}

			wp.hub.send(decryptProgress{
				TaskID:   id,
				File:     t.FileName,
				Progress: 100,
				State:    "complete",
				Output:   result.outputPath,
				Format:   result.format,
				Size:     result.sizeBytes,
			})
			updateDecryptDB(t.DBDir, func(db map[string]decryptEntry) {
				db[t.Hash] = decryptEntry{
					FileName:    t.FileName,
					DecryptedAt: time.Now().Format(time.RFC3339),
					SourceFile:  t.FilePath,
					OutputFile:  result.outputPath,
					Format:      result.format,
					Size:        result.sizeBytes,
				}
			})
			if t.IsUpload {
				os.Remove(t.FilePath)
			}
			}
		}
	}

// ============================================================
// #11  SSE Hub
// ============================================================

type sseHub struct {
	mu      sync.Mutex
	clients map[string][]chan decryptProgress // username -> channels
}

func newSSEHub() *sseHub {
	return &sseHub{
		clients: make(map[string][]chan decryptProgress),
	}
}

func (h *sseHub) subscribe(username string) chan decryptProgress {
	ch := make(chan decryptProgress, 64)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[username] = append(h.clients[username], ch)
	return ch
}

func (h *sseHub) unsubscribe(username string, ch chan decryptProgress) {
	h.mu.Lock()
	defer h.mu.Unlock()
	clients := h.clients[username]
	for i, c := range clients {
		if c == ch {
			h.clients[username] = append(clients[:i], clients[i+1:]...)
			close(c)
			return
		}
	}
}

func (h *sseHub) send(evt decryptProgress) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if evt.Username == "" {
		// Mode 0: broadcast to all clients
		for _, clients := range h.clients {
			for _, c := range clients {
				select {
				case c <- evt:
				default:
				}
			}
		}
		return
	}
	// Mode 1: only send to the event's target user
	for _, c := range h.clients[evt.Username] {
		select {
		case c <- evt:
		default:
		}
	}
}

// ============================================================
// #12  HTTP Server
// ============================================================

type server struct {
	mu     sync.RWMutex
	dir    string
	output string
	pool   *workerPool
	hub    *sseHub
	port   int
	host   string
	mode   int

	// Mode 1 (server deployment) specific
	users    *userStore
	sessions *sessionStore
	serverDir string
}

func newServer(dir, output string, workers, port int, host string, mode int, serverDir string) *server {
	hub := newSSEHub()
	pool := newWorkerPool(workers, output, hub)

	s := &server{
		dir:    dir,
		output: output,
		pool:   pool,
		hub:    hub,
		port:   port,
		host:   host,
		mode:   mode,
	}

	if mode == MODE_SERVER {
		os.MkdirAll(serverDir, 0755)
		s.serverDir = serverDir
		s.users = newUserStore(serverDir)
		s.sessions = newSessionStore()
	}

	return s
}

type fileEntry struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Hash     string `json:"hash"`
	Decrypted bool  `json:"decrypted"`
	ExistingSource string `json:"existing_source,omitempty"`
}

func (s *server) getDir() string   { s.mu.RLock(); defer s.mu.RUnlock(); return s.dir }
func (s *server) getOutput() string { s.mu.RLock(); defer s.mu.RUnlock(); return s.output }
func (s *server) setDir(d string)   { s.mu.Lock(); defer s.mu.Unlock(); s.dir = d }
func (s *server) setOutput(d string) { s.mu.Lock(); s.output = d; s.mu.Unlock(); s.pool.setOutput(d) }

// resolveDirs returns the data and output directories for the current request.
// In mode 0, returns the server's configured dir/output.
// In mode 1, returns the authenticated user's sandbox directories.
func (s *server) resolveDirs(r *http.Request) (dataDir, outputDir string, username string, err error) {
	if s.mode == MODE_LOCAL {
		return s.getDir(), s.getOutput(), "", nil
	}

	// Mode 1: resolve from session
	username, err = s.getSessionUser(r)
	if err != nil {
		return "", "", "", err
	}

	userBase := filepath.Join(s.serverDir, "users", username)
	dataDir = filepath.Join(userBase, "data")
	outputDir = filepath.Join(userBase, "output")
	os.MkdirAll(dataDir, 0755)
	os.MkdirAll(outputDir, 0755)
	return
}

// getSessionUser extracts the authenticated username from the request.
func (s *server) getSessionUser(r *http.Request) (string, error) {
	token := extractBearerToken(r)
	if token == "" {
		return "", errors.New("unauthorized")
	}
	username, ok := s.sessions.getUsername(token)
	if !ok {
		return "", errors.New("invalid session")
	}
	return username, nil
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	// Also check cookie
	c, err := r.Cookie("ncm_token")
	if err == nil {
		return c.Value
	}
	// Also check query parameter (for direct download links)
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}
	return ""
}

// authRequired is HTTP middleware that ensures the request is authenticated (mode 1 only).
// In mode 0 it's a no-op.
func (s *server) authRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.mode == MODE_SERVER {
			_, err := s.getSessionUser(r)
			if err != nil {
				http.Error(w, `{"error":"unauthorized","message":"请先登录 / Please login first"}`, http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

// ============================================================
// #13  Auth Handlers (Mode 1)
// ============================================================

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "bad request"})
		return
	}

	if err := s.users.register(req.Username, req.Password); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Create user sandbox directories
	userBase := filepath.Join(s.serverDir, "users", req.Username)
	os.MkdirAll(filepath.Join(userBase, "data"), 0755)
	os.MkdirAll(filepath.Join(userBase, "output"), 0755)

	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "注册成功 / Registration successful"})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "bad request"})
		return
	}

	if !s.users.authenticate(req.Username, req.Password) {
		json.NewEncoder(w).Encode(map[string]string{"error": "用户名或密码错误 / Invalid username or password"})
		return
	}

	token := s.sessions.create(req.Username)

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "ncm_token",
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		MaxAge:   86400 * 7, // 7 days
	})

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"token":    token,
		"username": req.Username,
	})
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}

	token := extractBearerToken(r)
	if token != "" {
		s.sessions.remove(token)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "ncm_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
	})

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	username, err := s.getSessionUser(r)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"authenticated": false})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      username,
	})
}

// ============================================================
// #14  API Handlers
// ============================================================

func (s *server) handleList(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		dataDir, outDir, _, err := s.resolveDirs(r)
		if err != nil {
			json.NewEncoder(w).Encode([]fileEntry{})
			return
		}
		entries, err := os.ReadDir(dataDir)
		if err != nil {
			json.NewEncoder(w).Encode([]fileEntry{})
			return
		}
		db := loadDecryptDB(outDir)
		var files []fileEntry
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".ncm") {
				continue
			}
			fi, _ := e.Info()
			path := filepath.Join(dataDir, e.Name())
			f, err := os.Open(path)
			var hash string
			if err == nil {
				h := sha256.New()
				io.Copy(h, f)
				hash = fmt.Sprintf("%x", h.Sum(nil))
				f.Close()
			}
			_, inDB := db[hash]
			decrypted := inDB
			if !decrypted {
				for _, ext := range []string{".mp3", ".flac", ".m4a", ".wav", ".ogg", ".aiff", ".ape", ".audio"} {
					base := strings.TrimSuffix(e.Name(), ".ncm")
					outPath := filepath.Join(outDir, base+ext)
					if _, err := os.Stat(outPath); err == nil {
						decrypted = true
						break
					}
				}
			}
				existingSource := ""
				if entry, ok := db[hash]; ok && entry.SourceFile != "" && filepath.Dir(entry.SourceFile) != dataDir {
					existingSource = entry.SourceFile
				}
				files = append(files, fileEntry{
				Name:      e.Name(),
				ExistingSource: existingSource,
				Size:      fi.Size(),
				Hash:      hash,
				Decrypted: decrypted,
			})
		}
		sort.Slice(files, func(i, j int) bool {
			return files[i].Name < files[j].Name
		})
		json.NewEncoder(w).Encode(files)
	}


func (s *server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Files []string `json:"files"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, 400)
		return
	}

	dataDir, outDir, _, err := s.resolveDirs(r)
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return
	}

	var ids []string
	db := loadDecryptDB(outDir)
	for _, name := range req.Files {
		name = filepath.Base(name)
		path := filepath.Join(dataDir, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		// Skip if already in decryption DB (by hash)
		h := sha256.New()
		if f, err := os.Open(path); err == nil {
			io.Copy(h, f)
			f.Close()
		}
		hash := fmt.Sprintf("%x", h.Sum(nil))
		if _, found := db[hash]; found {
			log.Printf("  skip (already decrypted): %s", name)
			continue
		}
		id, err := s.pool.enqueue(path, false, outDir)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_ids": ids,
		"count":    len(ids),
	})
}


func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", 500)
			return
		}
		// Get authenticated username
		username, err := s.getSessionUser(r)
		if err != nil {
			username = "_anonymous"
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		ch := s.hub.subscribe(username)
		defer s.hub.unsubscribe(username, ch)

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-ch:
				if !ok {
					return
				}
				data, _ := json.Marshal(evt)
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.State, data)
				flusher.Flush()
			}
		}
	}

func (s *server) handleDownload(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if file == "" {
			http.Error(w, "missing file", 400)
			return
		}

		_, outDir, _, err := s.resolveDirs(r)
		if err != nil {
			http.Error(w, "unauthorized", 401)
			return
		}

		// Only allow files from output dir (prevent path traversal)
		clean := filepath.Base(file)
		path := filepath.Join(outDir, clean)
		if _, err := os.Stat(path); err != nil {
			http.Error(w, "file not found", 404)
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename=\""+clean+"\"")
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, path)
	}

func (s *server) handleClean(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Files []string `json:"files"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "bad request"})
		return
	}

	dataDir, outDir, _, err := s.resolveDirs(r)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
		return
	}

	var deleted, failed int
	for _, name := range req.Files {
		name = filepath.Base(name)
		if !strings.HasSuffix(strings.ToLower(name), ".ncm") {
			continue
		}
		// Check if output exists
		hasOutput := false
		for _, ext := range []string{".mp3", ".flac", ".m4a", ".wav", ".ogg"} {
			base := strings.TrimSuffix(name, ".ncm")
			outPath := filepath.Join(outDir, base+ext)
			if _, err := os.Stat(outPath); err == nil {
				hasOutput = true
				break
			}
		}
		if !hasOutput {
			continue
		}
		path := filepath.Join(dataDir, name)
		if err := os.Remove(path); err != nil {
			failed++
		} else {
			deleted++
		}
	}

	json.NewEncoder(w).Encode(map[string]int{
		"deleted": deleted,
		"failed":  failed,
	})
}

func (s *server) handleListOutput(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, outDir, _, err := s.resolveDirs(r)
		if err != nil {
			json.NewEncoder(w).Encode([]map[string]interface{}{})
			return
		}
		entries, err := os.ReadDir(outDir)
		if err != nil {
			json.NewEncoder(w).Encode([]map[string]interface{}{})
			return
		}
		var files []map[string]interface{}
		audioExt := map[string]bool{
			".mp3": true, ".flac": true, ".m4a": true,
			".wav": true, ".ogg": true, ".aiff": true,
			".ape": true, ".audio": true,
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if !audioExt[strings.ToLower(filepath.Ext(e.Name()))] {
				continue
			}
			fi, _ := e.Info()
			if fi != nil {
				files = append(files, map[string]interface{}{
					"name": e.Name(),
					"size": fi.Size(),
				})
			}
		}
		json.NewEncoder(w).Encode(files)
	}

func (s *server) handleDedup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Files []string `json:"files"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"duplicates": []string{}})
		return
	}

	dataDir, _, _, err := s.resolveDirs(r)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"duplicates": []string{}})
		return
	}

	// Compute hashes for all requested files
	hashes := make(map[string]string)   // hash -> first file
	var duplicates []string
	for _, name := range req.Files {
		name = filepath.Base(name)
		path := filepath.Join(dataDir, name)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		h := sha256.New()
		io.Copy(h, f)
		f.Close()
		hash := fmt.Sprintf("%x", h.Sum(nil))
		if first, ok := hashes[hash]; ok {
			duplicates = append(duplicates, name)
			_ = first
		} else {
			hashes[hash] = name
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"duplicates": duplicates,
	})
}

// ============================================================
// #15  Upload endpoint
// ============================================================

func (s *server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if err := r.ParseMultipartForm(100 << 20); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "upload too large"})
		return
	}

	dataDir, _, _, err := s.resolveDirs(r)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
		return
	}

	files := r.MultipartForm.File["files"]
	var uploadCount int
	var results []map[string]string

	for _, fh := range files {
		name := filepath.Base(fh.Filename)
		if !strings.HasSuffix(strings.ToLower(name), ".ncm") {
			continue
		}
		targetPath := filepath.Join(dataDir, name)

		// Check if file with same name already exists
		exists := false
		if _, err := os.Stat(targetPath); err == nil {
			exists = true
		}

		if exists {
			results = append(results, map[string]string{
				"name":   name,
				"action": "exists",
			})
			continue
		}

		// New file — write to data dir
		src, err := fh.Open()
		if err != nil {
			continue
		}
		dst, err := os.Create(targetPath)
		if err != nil {
			src.Close()
			continue
		}
		_, err = io.Copy(dst, src)
		src.Close()
		dst.Close()
		if err != nil {
			os.Remove(targetPath)
			continue
		}
		uploadCount++
		results = append(results, map[string]string{
			"name":   name,
			"action": "uploaded",
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":   uploadCount,
		"files":   results,
	})
}

func (s *server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.mode == MODE_SERVER {
		// In server mode, return mode info and user-facing paths
		username, _ := s.getSessionUser(r)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mode":       s.mode,
			"username":   username,
			"server_dir": s.serverDir,
		})
		return
	}

	// Mode 0: return directory paths as before
	absDir, _ := filepath.Abs(s.getDir())
	absOut, _ := filepath.Abs(s.getOutput())
	json.NewEncoder(w).Encode(map[string]interface{}{
		"mode":       s.mode,
		"data_dir":  absDir,
		"output_dir": absOut,
	})
}

// handleExplorer lists subdirectories for the directory picker (mode 0 only).
func (s *server) handleExplorer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.mode == MODE_SERVER {
		// In server mode, directory browsing is not available
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":       "not available in server mode",
			"directories": []interface{}{},
			"shortcuts":   []interface{}{},
		})
		return
	}

	path := r.URL.Query().Get("path")
	if path == "" {
		path = s.getDir()
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "invalid path"})
		return
	}
	info, err := os.Stat(absPath)
	if err != nil || !info.IsDir() {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "not found"})
		return
	}
	entries, err := os.ReadDir(absPath)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "cannot read"})
		return
	}
	type dirEntry struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	var dirs []dirEntry
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		dirs = append(dirs, dirEntry{Name: e.Name(), Path: filepath.Join(absPath, e.Name())})
	}
	type shortcut struct {
		Label string `json:"label"`
		Path  string `json:"path"`
	}
	home, _ := os.UserHomeDir()
	var shortcuts []shortcut
	if home != "" {
		shortcuts = append(shortcuts,
			shortcut{Label: "Home (~)", Path: home},
			shortcut{Label: "Music", Path: filepath.Join(home, "Music")},
			shortcut{Label: "Downloads", Path: filepath.Join(home, "Downloads")},
		)
		storage := filepath.Join(home, "storage")
		if st, err := os.Stat(storage); err == nil && st.IsDir() {
			shortcuts = append(shortcuts,
				shortcut{Label: "Music (Shared)", Path: filepath.Join(storage, "music")},
				shortcut{Label: "Downloads (Shared)", Path: filepath.Join(storage, "downloads")},
			)
		}
	}
	if st, err := os.Stat("/sdcard"); err == nil && st.IsDir() {
		shortcuts = append(shortcuts, shortcut{Label: "SDCard", Path: "/sdcard"})
	}
	parent := filepath.Dir(absPath)
	if parent == absPath {
		parent = ""
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"current":     absPath,
		"parent":      parent,
		"directories": dirs,
		"shortcuts":   shortcuts,
	})
}

// handleSettings updates data/output directories via POST.
func (s *server) handleSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.mode == MODE_SERVER {
		json.NewEncoder(w).Encode(map[string]string{"error": "settings not available in server mode"})
		return
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "POST required"})
		return
	}
	var req struct {
		DataDir   string `json:"data_dir"`
		OutputDir string `json:"output_dir"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "bad request"})
		return
	}
	if req.DataDir != "" {
		if abs, err := filepath.Abs(req.DataDir); err == nil {
			if info, err := os.Stat(abs); err == nil && info.IsDir() {
				s.setDir(abs)
			}
		}
	}
	if req.OutputDir != "" {
		if abs, err := filepath.Abs(req.OutputDir); err == nil {
			os.MkdirAll(abs, 0755)
			s.setOutput(abs)
		}
	}
	json.NewEncoder(w).Encode(map[string]string{
		"data_dir":   s.getDir(),
		"output_dir": s.getOutput(),
	})
}


// handleResolve handles cross-directory copy/move/skip.
func (s *server) handleResolve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}
	var req struct {
		Action string `json:"action"` // copy | move | skip
		Hash   string `json:"hash"`
		Name   string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "bad request"})
		return
	}
	if req.Action == "" || req.Hash == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "missing action or hash"})
		return
	}

	_, outDir, _, err := s.resolveDirs(r)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	// Look up the source from DB
	var entry decryptEntry
	var found bool
	updateDecryptDB(outDir, func(db map[string]decryptEntry) {
		entry, found = db[req.Hash]
	})
	if !found || entry.SourceFile == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "source not found in DB"})
		return
	}
	srcPath := entry.SourceFile
	dstPath := filepath.Join(filepath.Dir(outDir), "data", req.Name)

	switch req.Action {
	case "copy":
		input, err := os.Open(srcPath)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "source not accessible"})
			return
		}
		defer input.Close()
		output, err := os.Create(dstPath)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "cannot create target"})
			return
		}
		defer output.Close()
		io.Copy(output, input)
	case "move":
		if err := os.Rename(srcPath, dstPath); err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "move failed: " + err.Error()})
			return
		}
		// Update DB with new path
		p := dstPath
		h := req.Hash
		updateDecryptDB(outDir, func(db map[string]decryptEntry) {
			if e, ok := db[h]; ok {
				e.SourceFile = p
				db[h] = e
			}
		})
	case "skip":
		// nothing extra
	default:
		json.NewEncoder(w).Encode(map[string]string{"error": "unknown action"})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "action": req.Action})
}

// handleDebug decrypts a single NCM file and returns diagnostic info.
func (s *server) handleDebug(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fileName := r.URL.Query().Get("file")
	if fileName == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "missing ?file= param"})
		return
	}

	dataDir, _, _, err := s.resolveDirs(r)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	path := filepath.Join(dataDir, filepath.Base(fileName))
	f, err := os.Open(path)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	defer f.Close()

	fi, _ := f.Stat()
	info := map[string]interface{}{
		"file":      fileName,
		"file_size": fi.Size(),
	}

	h, err := parseNCMHeader(f)
	if err != nil {
		info["error"] = err.Error()
		json.NewEncoder(w).Encode(info)
		return
	}
	info["audio_offset"] = h.audioOffset
	info["key_blob_len"] = len(h.keyBlob)
	info["meta_blob_len"] = len(h.metaBlob)
	info["cover_len"] = len(h.coverData)

	rc4Key, err := deriveRC4Key(h.keyBlob)
	if err != nil {
		info["kdf_error"] = err.Error()
		json.NewEncoder(w).Encode(info)
		return
	}
	info["rc4_key_len"] = len(rc4Key)
	n := 32
	if len(rc4Key) < n {
		n = len(rc4Key)
	}
	info["rc4_key_hex"] = fmt.Sprintf("% x", rc4Key[:n])

	rc4 := newNCMRC4(rc4Key)
	sampleSize := int64(4096)
	if fi.Size()-h.audioOffset < sampleSize {
		sampleSize = fi.Size() - h.audioOffset
	}
	if sampleSize < 4 {
		info["error"] = "file too small for audio"
		json.NewEncoder(w).Encode(info)
		return
	}
	sampler := make([]byte, sampleSize)
	if _, err := io.ReadFull(f, sampler); err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		info["sample_error"] = err.Error()
		json.NewEncoder(w).Encode(info)
		return
	}
	rc4.decrypt(sampler, h.audioOffset)
	n2 := 64
	if len(sampler) < n2 {
		n2 = len(sampler)
	}
	info["decrypted_hex"] = fmt.Sprintf("% x", sampler[:n2])
	info["detected_format"] = detectFormat(sampler)

	json.NewEncoder(w).Encode(info)
}

// handleServerInfo returns the mode and server info (used by frontend)
func (s *server) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"mode": s.mode,
		"name": "NCM Decrypt",
	})
}


// ============================================================
// #16  i18n API
// ============================================================

// handleLang returns translation strings for the requested locale.
func (s *server) handleLang(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	locale := r.URL.Query().Get("locale")
	if locale == "" {
		locale = detectLocale(r.Header.Get("Accept-Language"))
	}
	// Return the requested locale's translations, with all locales listed for the language picker
	resp := map[string]interface{}{
		"locale":             locale,
		"strings":            translations[locale],
		"supported_locales":  supportedLocales,
		"locale_names":       map[string]string{},
	}
	// Add locale display names
	nameMap := resp["locale_names"].(map[string]string)
	for _, l := range supportedLocales {
		nameMap[l] = t(l, "lang_name")
	}
	if translations[locale] == nil {
		resp["strings"] = translations["en"]
	}
	json.NewEncoder(w).Encode(resp)
}

// ============================================================
// #17  File Manager API
// ============================================================

// handleLs lists files and directories inside a user's sandbox.
func (s *server) handleLs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	_, outDir, _, err := s.resolveDirs(r)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized", "items": []interface{}{}})
		return
	}
	// The sandbox root is the parent of data/ and output/
	sandboxRoot := filepath.Dir(outDir) // serverDir/users/{username}
	subPath := r.URL.Query().Get("path")
	if subPath == "" || subPath == "/" {
		// Return the two main directories
		items := []map[string]interface{}{
			{"name": "data", "type": "dir", "path": "/data"},
			{"name": "output", "type": "dir", "path": "/output"},
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"items": items, "current": "/"})
		return
	}

	// Resolve sandbox path
	reqPath, err := safeJoin(sandboxRoot, strings.TrimPrefix(subPath, "/"))
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "invalid path", "items": []interface{}{}})
		return
	}

	info, err := os.Stat(reqPath)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "path not found", "items": []interface{}{}})
		return
	}
	if !info.IsDir() {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "not a directory", "items": []interface{}{}})
		return
	}

	entries, err := os.ReadDir(reqPath)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "cannot read directory", "items": []interface{}{}})
		return
	}

	var items []map[string]interface{}
	for _, e := range entries {
		fi, _ := e.Info()
		entryPath := filepath.Join(subPath, e.Name())
		item := map[string]interface{}{
			"name": e.Name(),
			"path": entryPath,
		}
		if e.IsDir() {
			item["type"] = "dir"
		} else {
			item["type"] = "file"
			item["size"] = fi.Size()
			item["ext"] = strings.ToLower(filepath.Ext(e.Name()))
		}
		items = append(items, item)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items":   items,
		"current": subPath,
	})
}

// handleMkdir creates a directory inside the user's sandbox.
func (s *server) handleMkdir(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "bad request"})
		return
	}

	_, outDir, _, err := s.resolveDirs(r)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}
	sandboxRoot := filepath.Dir(outDir)

	fullPath, err := safeJoin(sandboxRoot, strings.TrimPrefix(req.Path, "/"))
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid path"})
		return
	}

	if err := os.MkdirAll(fullPath, 0755); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "mkdir failed"})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleRm deletes a file or directory inside the user's sandbox.
func (s *server) handleRm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}

	var req struct {
		Path   string `json:"path"`
		Recursive bool `json:"recursive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "bad request"})
		return
	}

	_, outDir, _, err := s.resolveDirs(r)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}
	sandboxRoot := filepath.Dir(outDir)

	fullPath, err := safeJoin(sandboxRoot, strings.TrimPrefix(req.Path, "/"))
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid path"})
		return
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		return
	}

	if info.IsDir() {
		if req.Recursive {
			if err := os.RemoveAll(fullPath); err != nil {
				json.NewEncoder(w).Encode(map[string]string{"error": "remove failed"})
				return
			}
		} else {
			if err := os.Remove(fullPath); err != nil {
				json.NewEncoder(w).Encode(map[string]string{"error": "directory not empty or remove failed"})
				return
			}
		}
	} else {
		if err := os.Remove(fullPath); err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "remove failed"})
			return
		}
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleMv renames or moves a file/directory inside the user's sandbox.
func (s *server) handleMv(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}

	var req struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.From == "" || req.To == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "bad request"})
		return
	}

	_, outDir, _, err := s.resolveDirs(r)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}
	sandboxRoot := filepath.Dir(outDir)

	fromPath, err := safeJoin(sandboxRoot, strings.TrimPrefix(req.From, "/"))
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid from path"})
		return
	}
	toPath, err := safeJoin(sandboxRoot, strings.TrimPrefix(req.To, "/"))
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid to path"})
		return
	}

	if err := os.Rename(fromPath, toPath); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "rename failed"})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleFileDownload downloads any file from the user's sandbox (improved version).
func (s *server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("file")
	if filePath == "" {
		http.Error(w, "missing file", 400)
		return
	}

	_, outDir, _, err := s.resolveDirs(r)
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	sandboxRoot := filepath.Dir(outDir)

	fullPath, err := safeJoin(sandboxRoot, strings.TrimPrefix(filePath, "/"))
	if err != nil {
		http.Error(w, "invalid path", 400)
		return
	}

	info, err := os.Stat(fullPath)
	if err != nil || info.IsDir() {
		http.Error(w, "file not found", 404)
		return
	}

	clean := filepath.Base(fullPath)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", clean))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, fullPath)
}
// ============================================================
// #16  main()
// ============================================================

func main() {
	port := flag.Int("port", 8080, "port to listen on")
	host := flag.String("host", "0.0.0.0", "host to bind to")
	dir := flag.String("dir", ".", "directory containing .ncm files")
	output := flag.String("output", "./output", "output directory for decrypted files")
	workers := flag.Int("workers", 3, "number of concurrent workers")
	modeFlag := flag.Int("mode", -1, "运行模式 / mode: 0=本地(local) 1=服务器(server)")
	serverDir := flag.String("server-dir", "./server-data", "server mode data directory")
	flag.Parse()

	// Mode resolution: CLI flag > saved config > default (local)
	mode := *modeFlag
	if mode < 0 || mode > 1 {
		saved := loadSavedMode()
		if saved == MODE_LOCAL || saved == MODE_SERVER {
			mode = saved
			log.Printf("  使用上次运行模式: %d (%s)", mode, map[int]string{MODE_LOCAL: "本地 / Local", MODE_SERVER: "服务器 / Server"}[mode])
		} else {
			mode = MODE_LOCAL
		}
	}
	saveMode(mode) // persist for next launch

	absDir, _ := filepath.Abs(*dir)
	absOut, _ := filepath.Abs(*output)
	absServerDir, _ := filepath.Abs(*serverDir)

	log.Printf("NCM Decrypt starting...")
	log.Printf("  运行模式: %s", map[int]string{MODE_LOCAL: "本地 / Local", MODE_SERVER: "服务器 / Server"}[mode])
	if mode == MODE_LOCAL {
		log.Printf("  数据目录: %s", absDir)
		log.Printf("  输出目录: %s", absOut)
	} else {
		log.Printf("  服务器目录: %s", absServerDir)
	}
	log.Printf("  工作线程: %d", *workers)
	log.Printf("  监听地址: %s:%d", *host, *port)

	if mode == MODE_LOCAL {
		os.MkdirAll(absOut, 0755)
	}

	s := newServer(absDir, absOut, *workers, *port, *host, mode, absServerDir)
	s.pool.start()

	mux := http.NewServeMux()

	// Auth endpoints (mode 1 only, no auth required)
	if mode == MODE_SERVER {
		mux.HandleFunc("/api/info", s.handleServerInfo)
		mux.HandleFunc("/api/register", s.handleRegister)
		mux.HandleFunc("/api/login", s.handleLogin)
		mux.HandleFunc("/api/logout", s.handleLogout)
		mux.HandleFunc("/api/me", s.handleMe)
	} else {
		mux.HandleFunc("/api/info", s.handleServerInfo)
	}

	// Protected API endpoints (auth required in mode 1)
	mux.HandleFunc("/api/list", s.authRequired(s.handleList))
	mux.HandleFunc("/api/decrypt", s.authRequired(s.handleDecrypt))
	mux.HandleFunc("/api/events", s.handleEvents) // SSE, auth handled via resolveDirs
	mux.HandleFunc("/api/download", s.authRequired(s.handleDownload))
	mux.HandleFunc("/api/clean", s.authRequired(s.handleClean))
	mux.HandleFunc("/api/dedup", s.authRequired(s.handleDedup))
	mux.HandleFunc("/api/upload", s.authRequired(s.handleUpload))
	mux.HandleFunc("/api/outputs", s.authRequired(s.handleListOutput))
	mux.HandleFunc("/api/config", s.authRequired(s.handleConfig))
	mux.HandleFunc("/api/explorer", s.authRequired(s.handleExplorer))
	mux.HandleFunc("/api/settings", s.authRequired(s.handleSettings))
	mux.HandleFunc("/api/debug", s.authRequired(s.handleDebug))
	mux.HandleFunc("/api/resolve", s.authRequired(s.handleResolve))

		// i18n endpoint (no auth required)
	mux.HandleFunc("/api/lang", s.handleLang)

	// File manager endpoints (auth required)
	mux.HandleFunc("/api/ls", s.authRequired(s.handleLs))
	mux.HandleFunc("/api/mkdir", s.authRequired(s.handleMkdir))
	mux.HandleFunc("/api/rm", s.authRequired(s.handleRm))
	mux.HandleFunc("/api/mv", s.authRequired(s.handleMv))
	mux.HandleFunc("/api/file/download", s.authRequired(s.handleFileDownload))

	// Serve the single-page HTML frontend
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(htmlContent))
	})

	// CORS for local development
	handler := corsMiddleware(mux)

	addr := fmt.Sprintf("%s:%d", *host, *port)
	httpSrv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	log.Printf("")
	if mode == MODE_LOCAL {
		log.Printf("  浏览器打开: http://localhost:%d", *port)
	} else {
		log.Printf("  服务器模式 — 浏览器打开: http://localhost:%d", *port)
		log.Printf("  用户需先注册/登录后使用")
	}
	log.Printf("")

	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}
