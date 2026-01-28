package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/yl2chen/cidranger"
)

// ==========================================
// 1. 系统调用定义 (Syscall6 版)
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

// 打开 WinDivert
func winDivertOpen(filter string, layer int, priority int, flags int64) (uintptr, error) {
	cFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	// Syscall6 支持 6 个参数，Open 只有 4 个，后面补 0
	r1, _, err := syscall.Syscall6(
		procOpen.Addr(),
		4, // 参数个数
		uintptr(unsafe.Pointer(cFilter)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
		0, 0,
	)
	if r1 == 0 || r1 == ^uintptr(0) {
		return 0, fmt.Errorf("WinDivertOpen failed: %v", err)
	}
	return r1, nil
}

// 接收包 (关键修正)
func winDivertRecv(handle uintptr, buf []byte, addrPtr unsafe.Pointer) (int, error) {
	var readLen uint32 = 0
	
	// WinDivertRecv(handle, pPacket, packetLen, pAddr, pReadLen)
	// 5个参数
	r1, _, err := syscall.Syscall6(
		procRecv.Addr(),
		5, 
		handle,
		uintptr(unsafe.Pointer(&buf[0])), // pPacket
		uintptr(len(buf)),                // packetLen
		uintptr(addrPtr),                 // pAddr
		uintptr(unsafe.Pointer(&readLen)),// pReadLen (存放到栈变量)
		0,
	)

	if r1 == 0 {
		return 0, err // 返回系统错误 (LastErr)
	}
	
	// 双重保险：防止垃圾值导致 Panic
	if int(readLen) > len(buf) {
		return 0, fmt.Errorf("readLen overflow: %d", readLen)
	}
	
	return int(readLen), nil
}

// 发送包
func winDivertSend(handle uintptr, buf []byte, addrPtr unsafe.Pointer, writeLen int) error {
	var writtenLen uint32
	
	// WinDivertSend(handle, pPacket, packetLen, pAddr, pWriteLen)
	r1, _, err := syscall.Syscall6(
		procSend.Addr(),
		5,
		handle,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(writeLen),
		uintptr(addrPtr),
		uintptr(unsafe.Pointer(&writtenLen)),
		0,
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
	if err := initRanger("cidr.txt"); err != nil {
		fmt.Printf("读取 cidr.txt 失败: %v\n", err)
		return
	}

	// 使用定长数组保证内存布局稳定 (WinDivert Address 一般小于 128 字节)
	var addrBuf [128]byte
	packetBuf := make([]byte, 65535)

	fmt.Println("正在打开 WinDivert 驱动 (Inbound TCP RST)...")
	// 注意：必须管理员运行
	handle, err := winDivertOpen("inbound and tcp.Rst", WINDIVERT_LAYER_NETWORK, 0, 0)
	if err != nil {
		panic(fmt.Sprintf("启动失败: %v (请检查: 1.管理员权限 2.WinDivert.dll是否存在 3.架构是否匹配)", err))
	}
	defer syscall.Syscall(procClose.Addr(), 1, handle, 0, 0)

	fmt.Println("🛡️ RST 杀手已启动 (Syscall6 修复版)...")

	for {
		// 1. 接收包
		n, err := winDivertRecv(handle, packetBuf, unsafe.Pointer(&addrBuf[0]))
		if err != nil {
			// 忽略偶尔的 IO 错误
			continue
		}

		// 2. 检查长度 (防止 Panic 的最后防线)
		if n == 0 {
			continue
		}
		
		packet := packetBuf[:n]

		// 3. 解析 IP
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

		// 4. 判定
		contains, _ := ranger.Contains(srcIP)

		if contains {
			// ✅ 白名单，放行
			winDivertSend(handle, packet, unsafe.Pointer(&addrBuf[0]), n)
		} else {
			// 🗑️ 丢弃
			// fmt.Printf("🚫 丢弃 RST: %s\n", srcIP.String())
		}
	}
}