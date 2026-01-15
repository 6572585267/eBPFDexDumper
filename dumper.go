//go:build arm64

package main

/*
#cgo CFLAGS: -D_GNU_SOURCE
#include <sys/uio.h>
#include <unistd.h>
#include <stdint.h>

ssize_t readRemoteMem(pid_t pid, void *dst, size_t len, void *src) {
    struct iovec local_iov = { dst, len };
    struct iovec remote_iov = { src, len };
    return process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
}
*/
import "C"

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

type dexDumpHeader = bpfDexEventDataT
type methodEventHeader = bpfMethodEventDataT

var outputPath string

// decodeStruct 将data中的字节拷贝到结构体中（避免binary.Read开销）
func decodeStruct(data []byte, out unsafe.Pointer, size int) bool {
	if len(data) < size {
		return false
	}
	copy(unsafe.Slice((*byte)(out), size), data[:size])
	return true
}

// 方法事件处理任务
type methodTask struct {
	data []byte
}

// dexRecordBuffer 按DEX分组记录方法字节码，降低全局锁竞争
type dexRecordBuffer struct {
	mu      sync.Mutex
	records []MethodCodeRecord
}

type DexDumper struct {
	manager       *manager.Manager
	libArtPath    string
	uid           uint32
	trace         bool
	autoFix       bool
	executeOffset uint64
	nterpOffset   uint64

	// 使用sync.Map减少锁竞争（key: begin<<32 | methodIndex）
	methodSigCache sync.Map // key: uint64(begin<<32|methodIndex), value: string

	// 记录dex文件大小，便于生成文件名 dex<begin>_<size>_code.json
	dexSizesMu sync.RWMutex
	dexSizes   map[uint64]uint32 // Begin -> Size

	// 按DEX分组的记录缓存，避免全局锁竞争
	recordBuffers sync.Map // key: begin(uint64), value: *dexRecordBuffer

	// 分片接收状态：在Go侧重组eBPF分片
	pendingDexMu sync.Mutex
	pendingDex   map[uint64]*dexRecvState // Begin -> state

	// Worker pool for parallel method event processing
	methodTaskChan chan methodTask
	methodBufPool  sync.Pool
	workerWg       sync.WaitGroup
	stopped        atomic.Bool
}

// JSON导出条目
type MethodCodeRecord struct {
	Name      string `json:"name"`
	MethodIdx uint32 `json:"method_idx"`
	CodeHex   string `json:"code"`
}

//go:embed assets/*.btf
var embeddedAssets embed.FS

// Asset 从内置资源或文件系统加载
func Asset(filename string) ([]byte, error) {
	// Try embedded assets first (support both with and without assets/ prefix)
	if data, err := embeddedAssets.ReadFile(filename); err == nil {
		return data, nil
	}
	if !strings.HasPrefix(filename, "assets/") {
		if data, err := embeddedAssets.ReadFile("assets/" + filename); err == nil {
			return data, nil
		}
	}
	// Fallback to disk for dev/use outside embedding
	return ioutil.ReadFile(filename)
}

// methodSigCacheKey 统一生成方法签名缓存key，避免位移魔法数散落
func methodSigCacheKey(begin uint64, methodIdx uint32) uint64 {
	return (begin << 32) | uint64(methodIdx)
}

// getMethodBuf 从池中获取可复用缓冲区，减少分配
func (dd *DexDumper) getMethodBuf(size int) []byte {
	if v := dd.methodBufPool.Get(); v != nil {
		buf := v.([]byte)
		if cap(buf) >= size {
			return buf[:size]
		}
	}
	return make([]byte, size)
}

// putMethodBuf 回收缓冲区，限制过大切片避免内存占用膨胀
func (dd *DexDumper) putMethodBuf(buf []byte) {
	const maxMethodBufCap = 1 << 20 // 1MB
	if cap(buf) > maxMethodBufCap {
		return
	}
	dd.methodBufPool.Put(buf[:0])
}

func SetupManagerOptions() (manager.Options, error) {
	btfFile := ""
	bpfManagerOptions := manager.Options{}

	if !CheckConfig("CONFIG_DEBUG_INFO_BTF=y") {
		btfFile = FindBTFAssets()
	}

	if btfFile != "" {
		// 使用内置BTF，避免系统未开启CONFIG_DEBUG_INFO_BTF时加载失败
		var byteBuf []byte
		var err error

		byteBuf, err = Asset("assets/" + btfFile)
		if err != nil {
			byteBuf, err = Asset(btfFile)
			if err != nil {
				log.Printf("Warning: Failed to load BTF file %s: %v", btfFile, err)
				return manager.Options{
					RLimit: &unix.Rlimit{
						Cur: unix.RLIM_INFINITY,
						Max: unix.RLIM_INFINITY,
					},
				}, nil
			}
		}

		spec, err := btf.LoadSpecFromReader(bytes.NewReader(byteBuf))
		if err != nil {
			log.Printf("Warning: Failed to parse BTF spec: %v", err)
			return manager.Options{
				RLimit: &unix.Rlimit{
					Cur: unix.RLIM_INFINITY,
					Max: unix.RLIM_INFINITY,
				},
			}, nil
		}
		log.Printf("[+] Loaded BTF spec from %s", btfFile)
		// 配置Verifier参数，提升BPF加载兼容性与日志可读性
		bpfManagerOptions = manager.Options{
			DefaultKProbeMaxActive: 512,
			VerifierOptions: ebpf.CollectionOptions{
				Programs: ebpf.ProgramOptions{
					LogSize:     2097152,
					KernelTypes: spec,
				},
			},
			RLimit: &unix.Rlimit{
				Cur: math.MaxUint64,
				Max: math.MaxUint64,
			},
		}
	} else {
		// 无BTF时仍启用日志与资源限制，避免BPF加载失败
		bpfManagerOptions = manager.Options{
			DefaultKProbeMaxActive: 512,
			VerifierOptions: ebpf.CollectionOptions{
				Programs: ebpf.ProgramOptions{
					LogSize: 2097152,
				},
			},
			RLimit: &unix.Rlimit{
				Cur: math.MaxUint64,
				Max: math.MaxUint64,
			},
		}
	}
	return bpfManagerOptions, nil
}

func (dd *DexDumper) setupManager() error {
	offsetExecute, offsetExecuteNterp, offsetVerifyClass, err := FindArtOffsets(dd.libArtPath, dd.executeOffset, dd.nterpOffset)
	if err != nil {
		return err
	}

	// offsets are validated inside FindArtOffsets

	// 查找所有匹配的指令序列
	pattern := []byte{0x03, 0x0C, 0x40, 0xF9, 0x5F, 0x00, 0x03, 0xEB}
	patternUAddrs, err := findPatternUAddrs(dd.libArtPath, pattern)
	if err != nil {
		log.Printf("[-] pattern scan error: %v", err)
	} else {
		log.Printf("[+] found nterp_op_invoke_* %d pattern", len(patternUAddrs))
	}

	probes := []*manager.Probe{
		{
			UID:              "execute",
			EbpfFuncName:     "uprobe_libart_execute",
			Section:          "uprobe/libart_execute",
			BinaryPath:       dd.libArtPath,
			UAddress:         offsetExecute,
			AttachToFuncName: "Execute",
		},
		{
			UID:              "executeNterp",
			EbpfFuncName:     "uprobe_libart_executeNterpImpl",
			Section:          "uprobe/libart_executeNterpImpl",
			BinaryPath:       dd.libArtPath,
			UAddress:         offsetExecuteNterp,
			AttachToFuncName: "ExecuteNterpImpl",
		},
		// {
		// 	UID:              "verifyClass",
		// 	EbpfFuncName:     "uprobe_libart_verifyClass",
		// 	Section:          "uprobe/libart_verifyClass",
		// 	BinaryPath:       dd.libArtPath,
		// 	UAddress:         offsetVerifyClass,
		// 	AttachToFuncName: "VerifyClass",
		// },
	}

	for i, addr := range patternUAddrs {
		probes = append(probes, &manager.Probe{
			UID:              fmt.Sprintf("pattern_check_%d", i),
			EbpfFuncName:     "uprobe_libart_nterpOpInvoke",
			Section:          "uprobe/libart_nterpOpInvoke",
			BinaryPath:       dd.libArtPath,
			UAddress:         addr,
			AttachToFuncName: fmt.Sprintf("nterp_op_invoke_%d", i),
		})
	}

	dd.manager = &manager.Manager{
		Probes: probes,
		RingbufMaps: []*manager.RingbufMap{
			{
				Map: manager.Map{
					Name: "events",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					// DEX元信息事件（大小/起始地址等）
					DataHandler: dd.handleDexEventRingBuf,
				},
			},
			{
				Map: manager.Map{
					Name: "method_events",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					// 方法执行/字节码事件
					DataHandler: dd.handleMethodEventRingBuf,
				},
			},
			{
				Map: manager.Map{
					Name: "dex_chunks",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					// DEX分片数据事件
					DataHandler: dd.handleDexChunkEventRingBuf,
				},
			},
			{
				Map: manager.Map{
					Name: "read_failures",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					// 读取失败事件，触发Go侧readRemoteMem兜底
					DataHandler: dd.handleReadFailureEventRingBuf,
				},
			},
		},
	}

	log.Printf("[+] offsetExecute: %x offsetExecuteNterp: %x offsetVerifyClass: %x",
		offsetExecute, offsetExecuteNterp, offsetVerifyClass)
	return nil
}

// Start 启动 DexDumper
func (dd *DexDumper) Start(ctx context.Context) error {
	// 初始化manager与探针
	if err := dd.setupManager(); err != nil {
		return fmt.Errorf("failed to setup manager: %v", err)
	}

	// 加载BPF字节码
	options, err := SetupManagerOptions()
	if err != nil {
		return fmt.Errorf("failed to setup manager options: %v", err)
	}

	if err := dd.manager.InitWithOptions(bytes.NewReader(_BpfBytes), options); err != nil {
		return fmt.Errorf("failed to init manager: %v", err)
	}

	// 配置过滤参数
	configMap, found, err := dd.manager.GetMap("config_map")
	if err != nil {
		return fmt.Errorf("failed to get config map: %v", err)
	}
	if !found {
		return fmt.Errorf("config map not found")
	}

	config := bpfConfigT{
		Uid: dd.uid,
		Pid: 0,
	}

	// 将过滤配置写入BPF map（0号key）
	if err := configMap.Put(uint32(0), config); err != nil {
		return fmt.Errorf("failed to put config: %v", err)
	}

	log.Printf("[+] Filtering on uid %d", dd.uid)

	// 启动manager并开始接收事件
	if err := dd.manager.Start(); err != nil {
		return fmt.Errorf("failed to start manager: %v", err)
	}

	log.Printf("eBPF DexDumper started successfully")

	// 等待停止信号
	<-ctx.Done()

	return nil
}

// Stop 停止 DexDumper
func (dd *DexDumper) Stop() error {
	log.Printf("Stopping eBPF DexDumper")

	// 标记停止，阻止新事件进入
	dd.stopped.Store(true)

	// 先停止 manager，确保不再有新事件
	if dd.manager != nil {
		if err := dd.manager.Stop(manager.CleanAll); err != nil {
			log.Printf("Manager stop error: %v", err)
		}
	}

	// 然后关闭 worker pool
	close(dd.methodTaskChan)
	dd.workerWg.Wait()

	// 最后输出JSON，确保缓存清空
	dd.flushJSON()

	// 自动修复DEX文件
	if dd.autoFix {
		log.Printf("[+] Auto-fixing DEX files...")
		if err := FixDexDirectory(outputPath); err != nil {
			log.Printf("[!] Auto-fix failed: %v", err)
		}
	}
	return nil
}

const numWorkers = 4 // 并行处理 worker 数量

func NewDexDumper(libArtPath string, uid uint32, outputDir string, trace, autoFix bool, executeOffset, nterpOffset uint64) *DexDumper {
	outputPath = outputDir

	dd := &DexDumper{
		libArtPath:     libArtPath,
		uid:            uid,
		trace:          trace,
		autoFix:        autoFix,
		executeOffset:  executeOffset,
		nterpOffset:    nterpOffset,
		dexSizes:       make(map[uint64]uint32),
		pendingDex:     make(map[uint64]*dexRecvState),
		methodTaskChan: make(chan methodTask, 4096), // 缓冲通道
	}

	// 启动 worker pool
	for i := 0; i < numWorkers; i++ {
		dd.workerWg.Add(1)
		go dd.methodWorker()
	}

	return dd
}

// methodWorker 并行处理方法事件
func (dd *DexDumper) methodWorker() {
	defer dd.workerWg.Done()
	for task := range dd.methodTaskChan {
		dd.processMethodEvent(task.data)
		dd.putMethodBuf(task.data)
	}
}

// handleDexEventRingBuf 处理 Dex 文件事件 (RingBuffer版本)
func (dd *DexDumper) handleDexEventRingBuf(CPU int, data []byte, ringBuf *manager.RingbufMap, mgr *manager.Manager) {
	dexHeader := dexDumpHeader{}
	if !decodeStruct(data, unsafe.Pointer(&dexHeader), int(unsafe.Sizeof(dexDumpHeader{}))) {
		log.Printf("Read dex event failed")
		return
	}

	// 保存 dex 文件大小，供JSON导出文件名使用
	dd.dexSizesMu.Lock()
	dd.dexSizes[dexHeader.Begin] = dexHeader.Size
	dd.dexSizesMu.Unlock()

	// eBPF层已开始分片发送，此处不再 process_vm_readv。
	// 仅记录大小等元信息，等待 dex_chunks 重组完成。
}

func (dd *DexDumper) handleMethodEventRingBuf(CPU int, data []byte, perfMap *manager.RingbufMap, manager *manager.Manager) {
	if dd.stopped.Load() || len(data) < int(unsafe.Sizeof(methodEventHeader{})) {
		return
	}
	// 复制数据并分发到 worker pool
	dataCopy := dd.getMethodBuf(len(data))
	copy(dataCopy, data)
	select {
	case dd.methodTaskChan <- methodTask{data: dataCopy}:
	default:
		// 通道满时直接处理，避免阻塞 ringbuf
		dd.processMethodEvent(dataCopy)
		dd.putMethodBuf(dataCopy)
	}
}

// processMethodEvent 实际处理方法事件
func (dd *DexDumper) processMethodEvent(data []byte) {
	headerSize := int(unsafe.Sizeof(methodEventHeader{}))
	if len(data) < headerSize {
		return
	}
	methodHeader := methodEventHeader{}
	if !decodeStruct(data, unsafe.Pointer(&methodHeader), headerSize) {
		return
	}

	// Read bytecode if present
	var bytecode []byte
	if methodHeader.CodeitemSize > 0 {
		// 根据codeitem_size读取字节码，避免读入无效数据
		end := headerSize + int(methodHeader.CodeitemSize)
		if end > len(data) {
			return
		}
		bytecode = data[headerSize:end]
	}

	parser := dexCache.GetParser(methodHeader.Begin)

	var methodName string

	if parser == nil {
		// 当没有dex缓存时，使用方法idx作为methodName
		methodName = fmt.Sprintf("method_idx_%d", methodHeader.MethodIndex)
	} else {
		// 使用sync.Map无锁查询缓存
		cacheKey := methodSigCacheKey(methodHeader.Begin, methodHeader.MethodIndex)
		if cached, ok := dd.methodSigCache.Load(cacheKey); ok {
			methodName = cached.(string)
		} else {
			methodInfo, err := parser.GetMethodInfo(methodHeader.MethodIndex)
			if err != nil {
				methodName = fmt.Sprintf("method_idx_%d", methodHeader.MethodIndex)
			} else {
				methodName = methodInfo.PrettyMethod()
				// 存入缓存
				dd.methodSigCache.Store(cacheKey, methodName)
			}
		}
	}

	if methodHeader.CodeitemSize > 0 {
		if dd.trace {
			// trace模式下输出方法执行信息，便于实时定位
			log.Printf("%s (pid=%d, dex=0x%x, method_idx=%d, art_method=0x%x, bytecode_size=%d)",
				methodName,
				methodHeader.Pid,
				methodHeader.Begin,
				methodHeader.MethodIndex,
				methodHeader.ArtMethodPtr,
				methodHeader.CodeitemSize)
		}

		// 记录到每个dex的JSON导出缓存
		if len(bytecode) > 0 {
			rec := MethodCodeRecord{
				Name:      methodName,
				MethodIdx: methodHeader.MethodIndex,
				CodeHex:   hex.EncodeToString(bytecode),
			}
			// 以dex begin为分组，便于后续单独输出
			bufAny, _ := dd.recordBuffers.LoadOrStore(methodHeader.Begin, &dexRecordBuffer{})
			buf := bufAny.(*dexRecordBuffer)
			buf.mu.Lock()
			buf.records = append(buf.records, rec)
			buf.mu.Unlock()
		}
	} else {
		if dd.trace {
			log.Printf("%s (pid=%d, dex=0x%x, method_idx=%d, art_method=0x%x)",
				methodName,
				methodHeader.Pid,
				methodHeader.Begin,
				methodHeader.MethodIndex,
				methodHeader.ArtMethodPtr)
		}
	}
}

func (dd *DexDumper) flushJSON() {
	dd.dexSizesMu.RLock()
	sizes := make(map[uint64]uint32, len(dd.dexSizes))
	for k, v := range dd.dexSizes {
		sizes[k] = v
	}
	dd.dexSizesMu.RUnlock()

	// 按DEX文件分别输出JSON
	dd.recordBuffers.Range(func(key, value any) bool {
		begin := key.(uint64)
		buf := value.(*dexRecordBuffer)
		buf.mu.Lock()
		recs := buf.records
		if len(recs) > 0 {
			buf.records = nil
		}
		buf.mu.Unlock()
		if len(recs) == 0 {
			return true
		}

		size := sizes[begin]
		if size == 0 {
			if p := dexCache.GetParser(begin); p != nil {
				size = p.header.FileSize
			}
		}

		// 根据begin/size生成稳定文件名，避免覆盖
		fileName := fmt.Sprintf("%s/dex_%x_%x_code.json", outputPath, begin, size)
		f, err := os.Create(fileName)
		if err != nil {
			log.Printf("Create JSON file failed: %v", err)
			return true
		}

		// 使用bufio提升写入性能，JSON不缩进以减少体积与I/O
		writer := bufio.NewWriter(f)
		enc := json.NewEncoder(writer)
		if err := enc.Encode(recs); err != nil {
			log.Printf("Write JSON failed: %v", err)
		} else {
			writer.Flush()
			log.Printf("Saved code records to %s (%d entries)", fileName, len(recs))
		}
		f.Close()
		return true
	})
}

// 接收状态结构：重组 eBPF 分片
type dexRecvState struct {
	total uint32
	recv  uint32
	buf   []byte
}

// 限制单个DEX的最大大小，避免异常数据导致内存暴涨
const maxDexSize = 512 * 1024 * 1024 // 512MB

// saveDexFile 校验DEX有效性后写入文件并缓存解析结果
func (dd *DexDumper) saveDexFile(begin uint64, size uint32, data []byte) {
	if len(data) == 0 {
		log.Printf("Dex data empty for begin=0x%x", begin)
		return
	}

	// 解析头部校验魔数与结构完整性
	parser, err := NewDexParser(data)
	if err != nil {
		log.Printf("Invalid dex data (begin=0x%x): %v", begin, err)
		return
	}

	if parser.header.FileSize == 0 || parser.header.FileSize > maxDexSize {
		log.Printf("Dex header size invalid (begin=0x%x): %d", begin, parser.header.FileSize)
		return
	}
	if parser.header.HeaderSize != 0x70 {
		log.Printf("Dex header size mismatch (begin=0x%x): %d", begin, parser.header.HeaderSize)
		return
	}
	if size != 0 && parser.header.FileSize > size {
		log.Printf("Dex size mismatch (begin=0x%x): header=%d expect<=%d", begin, parser.header.FileSize, size)
		return
	}
	if int(parser.header.FileSize) > len(data) {
		log.Printf("Dex data truncated (begin=0x%x): header=%d data=%d", begin, parser.header.FileSize, len(data))
		return
	}

	// 写入缓存，供后续方法签名解析使用
	dexCache.AddDexParser(begin, parser)

	// 仅写入header声明的有效区间
	fileName := fmt.Sprintf("%s/dex_%x_%x.dex", outputPath, begin, parser.header.FileSize)
	if _, err := os.Stat(fileName); err == nil {
		// 文件已存在则跳过写入，减少I/O
		return
	}
	f, err := os.Create(fileName)
	if err != nil {
		log.Printf("Create file failed: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(data[:parser.header.FileSize]); err != nil {
		log.Printf("Write dexData failed: %v", err)
		return
	}
	log.Printf("Dex file saved to %s, size %d", fileName, parser.header.FileSize)
}

func (dd *DexDumper) handleDexChunkEventRingBuf(CPU int, data []byte, ringBuf *manager.RingbufMap, mgr *manager.Manager) {
	if len(data) < int(unsafe.Sizeof(bpfDexChunkEventT{})) {
		log.Printf("Dex chunk event too short: %d bytes", len(data))
		return
	}

	hdr := bpfDexChunkEventT{}
	if !decodeStruct(data, unsafe.Pointer(&hdr), int(unsafe.Sizeof(bpfDexChunkEventT{}))) {
		log.Printf("Read dex chunk header failed")
		return
	}
	if hdr.Size == 0 || hdr.Size > maxDexSize {
		log.Printf("Dex chunk size invalid: begin=0x%x size=%d", hdr.Begin, hdr.Size)
		return
	}

	// 直接切片引用ringbuf数据，避免额外分配
	headerSize := int(unsafe.Sizeof(bpfDexChunkEventT{}))
	payloadEnd := headerSize + int(hdr.DataLen)
	if payloadEnd > len(data) {
		log.Printf("Dex chunk payload out of bounds: %d > %d", payloadEnd, len(data))
		return
	}
	payload := data[headerSize:payloadEnd]

	begin := hdr.Begin
	dd.pendingDexMu.Lock()
	st, ok := dd.pendingDex[begin]
	if !ok {
		// init new state
		// 预分配完整Dex大小，保证分片写入定位一致
		st = &dexRecvState{total: hdr.Size, buf: make([]byte, hdr.Size)}
		dd.pendingDex[begin] = st
		// record size for later JSON name
		dd.dexSizesMu.Lock()
		dd.dexSizes[begin] = hdr.Size
		dd.dexSizesMu.Unlock()
	}
	// bounds check
	if uint64(hdr.Offset)+uint64(hdr.DataLen) <= uint64(len(st.buf)) {
		// 将分片数据拷贝到目标位置
		copy(st.buf[hdr.Offset:uint32(hdr.Offset)+hdr.DataLen], payload)
		// update received length conservatively; allow duplicates
		if st.recv < hdr.Offset+hdr.DataLen {
			st.recv = hdr.Offset + hdr.DataLen
		}
	}

	// completed?
	if st.recv >= st.total {
		dataCopy := st.buf
		// finalize
		delete(dd.pendingDex, begin)
		dd.pendingDexMu.Unlock()

		// 完整DEX重组后统一校验与输出
		dd.saveDexFile(begin, hdr.Size, dataCopy)
		return
	}
	dd.pendingDexMu.Unlock()
}

func (dd *DexDumper) handleReadFailureEventRingBuf(CPU int, data []byte, ringBuf *manager.RingbufMap, mgr *manager.Manager) {
	if len(data) < int(unsafe.Sizeof(bpfDexReadFailureT{})) {
		log.Printf("Read failure event too short: %d bytes", len(data))
		return
	}

	failureEvt := bpfDexReadFailureT{}
	if !decodeStruct(data, unsafe.Pointer(&failureEvt), int(unsafe.Sizeof(bpfDexReadFailureT{}))) {
		log.Printf("Read failure event failed")
		return
	}

	// log.Printf("eBPF read failed at offset %d for dex 0x%x (pid=%d), using readRemoteMem fallback",
	// 	failureEvt.FailedOffset, failureEvt.Begin, failureEvt.Pid)

	dd.readRemoteDexFallback(failureEvt.Begin, failureEvt.Pid, failureEvt.Size, failureEvt.FailedOffset)
}

func (dd *DexDumper) readRemoteDexFallback(begin uint64, pid uint32, totalSize uint32, startOffset uint32) {
	// 兜底通过process_vm_readv从目标进程读取DEX
	buf := make([]byte, totalSize)

	ret := C.readRemoteMem(C.pid_t(pid), unsafe.Pointer(&buf[0]), C.size_t(totalSize),
		unsafe.Pointer(uintptr(begin)))

	if ret < 0 {
		log.Printf("readRemoteMem failed for dex 0x%x: %d", begin, ret)
		return
	}

	readSize := uint32(ret)
	if readSize != totalSize {
		// 读取不足时裁剪，避免越界
		log.Printf("readRemoteMem partial read: expected %d, got %d", totalSize, readSize)
		buf = buf[:readSize]
	}

	// 兜底路径下也清理pending状态，避免重复拼接
	dd.pendingDexMu.Lock()
	delete(dd.pendingDex, begin)
	dd.pendingDexMu.Unlock()

	dd.dexSizesMu.Lock()
	dd.dexSizes[begin] = totalSize
	dd.dexSizesMu.Unlock()

	// 复用统一的校验与保存逻辑
	dd.saveDexFile(begin, totalSize, buf)
}
