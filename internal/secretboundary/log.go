package secretboundary

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

const logDownloadKey = "secretboundary.logDownload"
const logChunkSize = 32 << 10

type logDownload struct{ path, name string }

// DownloadLog defers file I/O to the response boundary, after it has obtained
// the index for the completed handler. Ordinary responses stay bounded.
func DownloadLog(c *gin.Context, path, name string) {
	if Protected(c) {
		c.Set(logDownloadKey, logDownload{path: path, name: name})
		return
	}
	c.FileAttachment(path, name)
}

func streamLog(w gin.ResponseWriter, header http.Header, idx *index, log logDownload) bool {
	f, err := os.Open(log.path)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}

	source := io.LimitReader(f, info.Size())
	overlap := max(0, idx.maxLogSecret-1)
	data := make([]byte, logChunkSize+overlap)
	n, err := io.ReadFull(source, data[:logChunkSize])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return false
	}
	header.Set("Content-Type", http.DetectContentType(data[:n]))
	switch mediaType(header) {
	case "text/plain", "application/octet-stream":
	default:
		return false
	}
	header.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": log.name}))
	header.Set("Cache-Control", "no-store")
	redactHeaders(w.Header(), header, idx)
	w.Header().Del("Content-Length")
	w.WriteHeader(http.StatusOK)
	w.WriteHeaderNow()

	if err != nil {
		_, _ = io.WriteString(w, idx.redact(string(data[:n])))
		return true
	}
	for {
		last := err != nil
		limit := n
		if !last {
			limit = max(0, n-overlap)
		}
		consumed, writeErr := idx.writeLogChunk(w, data[:n], limit)
		if last || writeErr != nil {
			return true
		}
		retained := copy(data, data[consumed:n])
		var read int
		read, err = io.ReadFull(source, data[retained:retained+logChunkSize])
		n = retained + read
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			// A partial read with an I/O error may end in the prefix of a credential.
			return true
		}
	}
}

// Match against the complete window, but start matches only in its stable
// prefix. A match crossing that prefix consumes its bytes from the overlap.
func (idx *index) writeLogChunk(w io.Writer, data []byte, limit int) (int, error) {
	start, pos := 0, 0
	for pos < limit {
		length := 0
		for _, secret := range idx.logSecrets[data[pos]] {
			if !bytes.HasPrefix(data[pos:], []byte(secret)) {
				continue
			}
			if _, err := w.Write(data[start:pos]); err != nil {
				return 0, err
			}
			if _, err := io.WriteString(w, idx.byValue[secret]); err != nil {
				return 0, err
			}
			length = len(secret)
			start = pos + length
			break
		}
		pos += max(1, length)
	}
	_, err := w.Write(data[start:pos])
	return pos, err
}
