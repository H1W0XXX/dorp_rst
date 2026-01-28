package main

import (
	"bufio"
	"flag" // 引入 flag 包处理命令行参数
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/yl2chen/cidranger"
)

// ==========================================
// 1. 系统调用定义 (Syscall6 版 - 保持不变)
// ==========================================

var (
	modWinDivert = syscall.NewLazyDLL("WinDivert.dll")
	procOpen     = modWinDivert.NewProc("WinDivertOpen")
	procRecv     = modWinDivert.NewProc("WinDivertRecv")
	procSend     = modWinDivert.NewProc("WinDivertSend")
	procClose    = modWinDivert.NewProc("WinDivertClose")
)

const (
	WINDIVERT_LAYER_NETWORK = 0
)

func winDivertOpen(filter string, layer int, priority int, flags int64) (uintptr, error) {
	cFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	r1, _, err := syscall.Syscall6(
		procOpen.Addr(), 4,
		uintptr(unsafe.Pointer(cFilter)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags), 0, 0,
	)
	if r1 == 0 || r1 == ^uintptr(0) {
		return 0, fmt.Errorf("WinDivertOpen failed: %v", err)
	}
	return r1, nil
}

func winDivertRecv(handle uintptr, buf []byte, addrPtr unsafe.Pointer) (int, error) {
	var readLen uint32 = 0
	r1, _, err := syscall.Syscall6(
		procRecv.Addr(), 5,
		handle,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(addrPtr),
		uintptr(unsafe.Pointer(&readLen)), 0,
	)
	if r1 == 0 {
		return 0, err
	}
	if int(readLen) > len(buf) {
		return 0, fmt.Errorf("readLen overflow")
	}
	return int(readLen), nil
}

func winDivertSend(handle uintptr, buf []byte, addrPtr unsafe.Pointer, writeLen int) error {
	var writtenLen uint32
	r1, _, err := syscall.Syscall6(
		procSend.Addr(), 5,
		handle,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(writeLen),
		uintptr(addrPtr),
		uintptr(unsafe.Pointer(&writtenLen)), 0,
	)
	if r1 == 0 {
		return err
	}
	return nil
}

// ==========================================
// 2. 业务逻辑
// ==========================================

var ranger cidranger.Ranger

func initRanger(filePath string) error {
	ranger = cidranger.NewPCTrieRanger()
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, network, err := net.ParseCIDR(line)
		if err != nil {
			fmt.Printf("⚠️ 跳过无效 CIDR: %s\n", line)
			continue
		}
		_ = ranger.Insert(cidranger.NewBasicRangerEntry(*network))
		count++
	}
	fmt.Printf("✅ 已加载 %d 条白名单规则。\n", count)
	return nil
}

func main() {
	// 定义命令行参数
	dropAll := flag.Bool("all", false, "如果不加此参数，则读取 cidr.txt 白名单；如果加了 -all，则丢弃所有入站 RST")
	flag.Parse()

	// 根据模式初始化
	if *dropAll {
		fmt.Println("🔥 模式: [全丢模式] 丢弃所有入站 RST，不需要 cidr.txt")
	} else {
		fmt.Println("🛡️ 模式: [白名单模式] 仅放行 cidr.txt 内的 RST")
		if err := initRanger("cidr.txt"); err != nil {
			fmt.Printf("读取 cidr.txt 失败: %v\n", err)
			fmt.Println("提示: 如果想无需文件直接丢弃所有包，请运行: .\\dorp_rst.exe -all")
			return
		}
	}

	var addrBuf [128]byte
	packetBuf := make([]byte, 65535)

	fmt.Println("正在打开 WinDivert 驱动 (Inbound TCP RST)...")
	handle, err := winDivertOpen("inbound and tcp.Rst", WINDIVERT_LAYER_NETWORK, 0, 0)
	if err != nil {
		panic(fmt.Sprintf("启动失败: %v", err))
	}
	defer syscall.Syscall(procClose.Addr(), 1, handle, 0, 0)

	fmt.Println("✅ 服务已启动，开始过滤...")

	for {
		// 1. 接收包
		n, err := winDivertRecv(handle, packetBuf, unsafe.Pointer(&addrBuf[0]))
		if err != nil || n == 0 {
			continue
		}
		packet := packetBuf[:n]

		// ==========================
		// 分支 1: 全丢模式 (-all)
		// ==========================
		if *dropAll {
			// 直接丢弃，啥也不干 (continue)
			// 为了看效果，可以把下面这行打印注释解开
			// fmt.Println("🚫 [全丢] 拦截到一个 RST")
			continue
		}

		// ==========================
		// 分支 2: 白名单模式 (默认)
		// ==========================
		
		// 解析 IP 用于比对
		if len(packet) < 1 { continue }
		version := packet[0] >> 4
		var srcIP net.IP

		if version == 4 {
			if len(packet) < 20 { continue }
			srcIP = net.IPv4(packet[12], packet[13], packet[14], packet[15])
		} else if version == 6 {
			if len(packet) < 40 { continue }
			srcIP = packet[8:24]
		} else {
			// 未知协议放行
			winDivertSend(handle, packet, unsafe.Pointer(&addrBuf[0]), n)
			continue
		}

		// 查表
		contains, _ := ranger.Contains(srcIP)

		if contains {
			// ✅ 白名单，放行
			winDivertSend(handle, packet, unsafe.Pointer(&addrBuf[0]), n)
		} else {
			// 🗑️ 丢弃
			// fmt.Printf("🚫 [白名单过滤] 丢弃 RST: %s\n", srcIP.String())
		}
	}
}