package main

import (
	"crypto/aes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/binary"
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
)

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
	// Scan for signatures at non-zero offsets (some files have extra header bytes)
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
		// Progress tracking via caller would need a callback
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
	SourceFile  string `json:"source_file"` // original .ncm path
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
	json.Unmarshal(data, &db)  // ignore corrupted DB
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

// quickID returns a fingerprint (first 8 bytes of SHA-256 of head+mid+tail).
func quickID(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, _ := f.Stat()
	if fi == nil {
		return ""
	}
	size := fi.Size()
	const cs = 1024
	buf := make([]byte, cs*3)
	io.ReadFull(f, buf[:cs])
	if size > cs*2 {
		f.ReadAt(buf[cs:cs*2], size/2)
	}
	if size > cs {
		f.ReadAt(buf[cs*2:], size-cs)
	}
	h := sha256.Sum256(buf)
	return fmt.Sprintf("%x", h[:8])
}

// ============================================================
// #9  Worker Pool

type decryptTask struct {
	ID       string
	FilePath string
	FileName string
	Hash     string
	Size     int64
	IsUpload bool   // auto-delete source after decrypt
	DBDir    string // directory for .decrypted.json
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
		ID:       id,
		FilePath: filePath,
		FileName: filepath.Base(filePath),
		Hash:     hash,
		Size:     size,
		IsUpload: isUpload,
		DBDir:    dbDir,
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

			result, err := decryptFile(t.FilePath, wp.output)
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
// #9  SSE Hub
// ============================================================

type sseHub struct {
	mu      sync.Mutex
	clients []chan decryptProgress
}

func newSSEHub() *sseHub {
	return &sseHub{}
}

func (h *sseHub) subscribe() chan decryptProgress {
	ch := make(chan decryptProgress, 64)
	h.mu.Lock()
	h.clients = append(h.clients, ch)
	h.mu.Unlock()
	return ch
}

func (h *sseHub) unsubscribe(ch chan decryptProgress) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, c := range h.clients {
		if c == ch {
			h.clients = append(h.clients[:i], h.clients[i+1:]...)
			close(c)
			return
		}
	}
}

func (h *sseHub) send(evt decryptProgress) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.clients {
		select {
		case c <- evt:
		default:
		}
	}
}

// ============================================================
// #10  HTTP Server
// ============================================================

type server struct {
	mu     sync.RWMutex
	dir    string
	output string
	pool   *workerPool
	hub    *sseHub
	port   int
	host   string
}

func newServer(dir, output string, workers, port int, host string) *server {
	hub := newSSEHub()
	pool := newWorkerPool(workers, output, hub)
	return &server{
		dir:    dir,
		output: output,
		pool:   pool,
		hub:    hub,
		port:   port,
		host:   host,
	}
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

func (s *server) handleList(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		dataDir := s.getDir()
		entries, err := os.ReadDir(dataDir)
		if err != nil {
			json.NewEncoder(w).Encode([]fileEntry{})
			return
		}
		outDir := s.getOutput()
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

	var ids []string
	db := loadDecryptDB(s.getOutput())
	for _, name := range req.Files {
		name = filepath.Base(name)
		path := filepath.Join(s.getDir(), name)
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
		id, err := s.pool.enqueue(path, false, s.getOutput())
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
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch := s.hub.subscribe()
	defer s.hub.unsubscribe(ch)

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
	// Only allow files from output dir (prevent path traversal)
	clean := filepath.Base(file)
	path := filepath.Join(s.getOutput(), clean)
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

	var deleted, failed int
		outDir := s.getOutput()
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
		path := filepath.Join(s.getDir(), name)
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
	entries, err := os.ReadDir(s.getOutput())
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
		Files []string `json:"files"` // list of filenames to check for duplicates
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"duplicates": []string{}})
		return
	}

	// Compute hashes for all requested files
	hashes := make(map[string]string)   // hash -> first file
	var duplicates []string
	for _, name := range req.Files {
		name = filepath.Base(name)
		path := filepath.Join(s.getDir(), name)
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
// #11  Server + upload endpoint
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

	files := r.MultipartForm.File["files"]
	dataDir := s.getDir()
	var uploadCount int
	var results []map[string]string

	for _, fh := range files {
		name := filepath.Base(fh.Filename)
		if !strings.HasSuffix(strings.ToLower(name), ".ncm") {
			continue
		}
		targetPath := filepath.Join(dataDir, name)

		// Check if file with same name already exists in data dir
		exists := false
		if _, err := os.Stat(targetPath); err == nil {
			exists = true
		}

		if exists {
			// File already exists — don't copy, just report it
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
	absDir, _ := filepath.Abs(s.getDir())
	absOut, _ := filepath.Abs(s.getOutput())
	json.NewEncoder(w).Encode(map[string]string{
		"data_dir":  absDir,
		"output_dir": absOut,
	})
}

// handleExplorer lists subdirectories for the directory picker.
func (s *server) handleExplorer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
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
	// Look up the source from DB
	var entry decryptEntry
	var found bool
	updateDecryptDB(s.getOutput(), func(db map[string]decryptEntry) {
		entry, found = db[req.Hash]
	})
	if !found || entry.SourceFile == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "source not found in DB"})
		return
	}
	srcPath := entry.SourceFile
	dstPath := filepath.Join(s.getDir(), req.Name)

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
		updateDecryptDB(s.getOutput(), func(db map[string]decryptEntry) {
			if e, ok := db[h]; ok {
				e.SourceFile = p
				db[h] = e
			}
		})
	case "skip":
		// nothing extra, just decrypt in place
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
	path := filepath.Join(s.getDir(), filepath.Base(fileName))
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

// ============================================================
// #12  main()
// ============================================================

func main() {
	port := flag.Int("port", 8080, "port to listen on")
	host := flag.String("host", "0.0.0.0", "host to bind to")
	dir := flag.String("dir", ".", "directory containing .ncm files")
	output := flag.String("output", "./output", "output directory for decrypted files")
	workers := flag.Int("workers", 3, "number of concurrent workers")
	flag.Parse()

	absDir, _ := filepath.Abs(*dir)
	absOut, _ := filepath.Abs(*output)
	log.Printf("NCM Decrypt starting...")
	log.Printf("  数据目录: %s", absDir)
	log.Printf("  输出目录: %s", absOut)
	log.Printf("  工作线程: %d", *workers)
	log.Printf("  监听地址: %s:%d", *host, *port)

	os.MkdirAll(absOut, 0755)

	s := newServer(absDir, absOut, *workers, *port, *host)
	s.pool.start()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/list", s.handleList)
	mux.HandleFunc("/api/decrypt", s.handleDecrypt)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/download", s.handleDownload)
	mux.HandleFunc("/api/clean", s.handleClean)
	mux.HandleFunc("/api/dedup", s.handleDedup)
	mux.HandleFunc("/api/upload", s.handleUpload)
	mux.HandleFunc("/api/outputs", s.handleListOutput)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/explorer", s.handleExplorer)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/debug", s.handleDebug)

	mux.HandleFunc("/api/resolve", s.handleResolve)
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
	log.Printf("  浏览器打开: http://localhost:%d", *port)
	log.Printf("")

	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}
