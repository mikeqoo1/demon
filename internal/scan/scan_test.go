package scan

import (
	"net"
	"reflect"
	"testing"
)

func TestParsePort(t *testing.T) {
	s := NewScan("127.0.0.1", "")
	cases := []struct {
		in      string
		want    []int
		wantErr bool
	}{
		{"80", []int{80}, false},
		{"80,81", []int{80, 81}, false},
		{"80|81|82", []int{80, 81, 82}, false},
		{"80-83", []int{80, 81, 82, 83}, false},
		{"80~82", []int{80, 81, 82}, false},
		{" 80 , 81 ", []int{80, 81}, false}, // 容許空白
		{"85-80", nil, true},                // 反向區間
		{"80,abc", nil, true},               // 壞列舉：不可靜靜塞 0
		{"abc-90", nil, true},               // 壞區間
		{"xyz", nil, true},                  // 壞單一
		{"", nil, true},                     // 空字串
	}
	for _, c := range cases {
		got, err := s.ParsePort(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParsePort(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParsePort(%q)=%v, want %v", c.in, got, c.want)
		}
	}
}

// TestScanPortsFindsOpenPort 開一個真的 TCP listener，確認有界 worker pool
// 掃得到它、且沒掃到沒開的鄰近 port。
func TestScanPortsFindsOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	s := NewScan("127.0.0.1", "")
	got := s.ScanPorts("127.0.0.1", openPort-2, openPort+2, 8)

	found := false
	for _, p := range got {
		if p == openPort {
			found = true
		}
		if p < openPort-2 || p > openPort+2 {
			t.Errorf("ScanPorts 回傳超出區間的 port %d", p)
		}
	}
	if !found {
		t.Errorf("ScanPorts 沒找到已開的 port %d，結果=%v", openPort, got)
	}
}

// TestScanPortsSorted 確認回傳是遞增排序。
func TestScanPortsSorted(t *testing.T) {
	l1, _ := net.Listen("tcp", "127.0.0.1:0")
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l1.Close()
	defer l2.Close()
	p1 := l1.Addr().(*net.TCPAddr).Port
	p2 := l2.Addr().(*net.TCPAddr).Port
	lo, hi := p1, p2
	if lo > hi {
		lo, hi = hi, lo
	}
	s := NewScan("127.0.0.1", "")
	got := s.ScanPorts("127.0.0.1", lo, hi, 16)
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("ScanPorts 結果未遞增排序: %v", got)
			break
		}
	}
}
