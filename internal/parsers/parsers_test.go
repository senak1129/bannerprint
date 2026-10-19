package parsers

import "testing"

// TestParsers 表驱动验证每个 Parser 的「语法判定 + 字段抽取」。
// 注意：这里断言的是**语法字段**，不是产品名 —— 产品判定属于 rules，不在本包职责内。
func TestParsers(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		banner   []byte
		wantOK   bool
		check    map[string]string
	}{
		{
			name:     "ssh with comment",
			protocol: "SSH",
			banner:   []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"),
			wantOK:   true,
			check:    map[string]string{"ssh.software": "OpenSSH_8.9p1", "ssh.comment": "Ubuntu-3"},
		},
		{
			name:     "ssh without comment",
			protocol: "SSH",
			banner:   []byte("SSH-1.99-OpenSSH_4.3"),
			wantOK:   true,
			check:    map[string]string{"ssh.software": "OpenSSH_4.3", "ssh.protoversion": "1.99"},
		},
		{
			name:     "ssh with leading noise",
			protocol: "SSH",
			banner:   []byte("welcome\r\nSSH-2.0-dropbear_2020.81\r\n"),
			wantOK:   true,
			check:    map[string]string{"ssh.software": "dropbear_2020.81"},
		},
		{
			name:     "http nginx",
			protocol: "HTTP",
			banner:   []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"),
			wantOK:   true,
			check:    map[string]string{"http.server": "nginx/1.24.0"},
		},
		{
			name:     "http case insensitive header",
			protocol: "HTTP",
			banner:   []byte("HTTP/1.1 404 Not Found\nserver:   Jetty/9.4.51  \n"),
			wantOK:   true,
			check:    map[string]string{"http.server": "Jetty/9.4.51"},
		},
		{
			name:     "http without server header",
			protocol: "HTTP",
			banner:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 0"),
			wantOK:   true,
			check:    map[string]string{"http.status_line": "HTTP/1.1 200 OK"},
		},
		{
			name:     "mysql handshake",
			protocol: "MySQL",
			banner:   []byte{'J', 0, 0, 0, 0x0A, '8', '.', '0', '.', '3', '2', 0},
			wantOK:   true,
			check:    map[string]string{"mysql.server_version": "8.0.32"},
		},
		{
			name:     "mysql handshake shifted by one byte",
			protocol: "MySQL",
			banner:   []byte{'J', 0, 0, 0, 0, 0x0A, '5', '.', '7', '.', '4', '2', 0},
			wantOK:   true,
			check:    map[string]string{"mysql.server_version": "5.7.42"},
		},
		{
			name:     "redis error",
			protocol: "Redis",
			banner:   []byte("-ERR wrong number of arguments for 'get' command\r\n"),
			wantOK:   true,
			check:    map[string]string{"redis.prefix": "-", "redis.reply": "-ERR wrong number of arguments for 'get' command"},
		},
		{
			name:     "ftp proftpd",
			protocol: "FTP",
			banner:   []byte("220 ProFTPD 1.3.7 Server (ProFTPD)\r\n"),
			wantOK:   true,
			check:    map[string]string{"ftp.code": "220", "ftp.text": "ProFTPD 1.3.7 Server (ProFTPD)"},
		},
		{
			name:     "tls record",
			protocol: "TLS",
			banner:   []byte{0x16, 0x03, 0x01, 0x00, 0xA5, 0x01, 0x00, 0x00, 0xA1},
			wantOK:   true,
			check:    map[string]string{"tls.record": "handshake"},
		},
		// 反例：语法上不属于任何协议
		{name: "plain text is not ssh", protocol: "SSH", banner: []byte("QUIT\r\n"), wantOK: false},
		{name: "plain text is not http", protocol: "HTTP", banner: []byte("QUIT\r\n"), wantOK: false},
		{name: "plain text is not ftp", protocol: "FTP", banner: []byte("QUIT\r\n"), wantOK: false},
		{name: "short binary is not tls", protocol: "TLS", banner: []byte{0x16, 0x03}, wantOK: false},
		{name: "http version byte is not tls", protocol: "TLS", banner: []byte{0x15, 0x03, 0x01}, wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p Parser
			for _, candidate := range All() {
				if candidate.Protocol() == tc.protocol {
					p = candidate
					break
				}
			}
			if p == nil {
				t.Fatalf("parser for %s not found", tc.protocol)
			}
			fields, ok := p.Parse(tc.banner)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (fields=%v)", ok, tc.wantOK, fields)
			}
			if !ok {
				return
			}
			for k, want := range tc.check {
				if got := fields[k]; got != want {
					t.Errorf("field %s = %q, want %q", k, got, want)
				}
			}
		})
	}
}

// TestAllDeterministic 保证解析器顺序稳定：顺序变化会影响同分候选的仲裁结果。
func TestAllDeterministic(t *testing.T) {
	first := All()
	second := All()
	if len(first) != len(second) {
		t.Fatalf("length mismatch: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Name() != second[i].Name() {
			t.Fatalf("order changed at %d: %s vs %s", i, first[i].Name(), second[i].Name())
		}
	}
}
