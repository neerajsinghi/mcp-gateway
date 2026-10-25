package gateway

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
)

// sseTransform returns a reader that re-emits the Server-Sent Events stream
// from src, passing each event's data payload through fn. Events are
// forwarded as soon as they are complete so streaming latency is preserved.
// Comment lines, ids, event names and retry fields are kept verbatim.
func sseTransform(src io.ReadCloser, fn func([]byte) []byte) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		br := bufio.NewReader(src)
		var event []string
		flush := func() error {
			if len(event) == 0 {
				return nil
			}
			_, err := pw.Write(rewriteEvent(event, fn))
			event = event[:0]
			return err
		}
		for {
			line, err := br.ReadString('\n')
			if line != "" {
				trimmed := strings.TrimRight(line, "\r\n")
				if trimmed == "" && strings.HasSuffix(line, "\n") {
					if werr := flush(); werr != nil {
						pw.CloseWithError(werr)
						return
					}
					if _, werr := pw.Write([]byte("\n")); werr != nil {
						pw.CloseWithError(werr)
						return
					}
				} else {
					event = append(event, trimmed)
				}
			}
			if err != nil {
				if ferr := flush(); ferr != nil {
					pw.CloseWithError(ferr)
					return
				}
				if errors.Is(err, io.EOF) {
					pw.Close()
				} else {
					pw.CloseWithError(err)
				}
				return
			}
		}
	}()
	return &pipeBody{PipeReader: pr, src: src}
}

// rewriteEvent rebuilds one SSE event (without its terminating blank line),
// replacing the joined data payload with fn(payload).
func rewriteEvent(lines []string, fn func([]byte) []byte) []byte {
	var data []string
	for _, l := range lines {
		if v, ok := fieldValue(l, "data"); ok {
			data = append(data, v)
		}
	}
	var out bytes.Buffer
	if len(data) == 0 {
		for _, l := range lines {
			out.WriteString(l)
			out.WriteByte('\n')
		}
		return out.Bytes()
	}
	payload := []byte(strings.Join(data, "\n"))
	replaced := fn(payload)
	wroteData := false
	for _, l := range lines {
		if _, ok := fieldValue(l, "data"); ok {
			if wroteData {
				continue
			}
			wroteData = true
			for _, part := range bytes.Split(replaced, []byte("\n")) {
				out.WriteString("data: ")
				out.Write(part)
				out.WriteByte('\n')
			}
			continue
		}
		out.WriteString(l)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// fieldValue parses an SSE line "name: value" or "name:value".
func fieldValue(line, name string) (string, bool) {
	if line == name {
		return "", true
	}
	rest, ok := strings.CutPrefix(line, name+":")
	if !ok {
		return "", false
	}
	return strings.TrimPrefix(rest, " "), true
}

// pipeBody closes both the pipe and the upstream body.
type pipeBody struct {
	*io.PipeReader
	src io.ReadCloser
}

func (p *pipeBody) Close() error {
	err := p.src.Close()
	p.PipeReader.Close()
	return err
}
