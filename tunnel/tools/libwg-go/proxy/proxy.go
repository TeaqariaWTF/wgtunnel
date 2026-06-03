package proxy

/*
#include "vpn_jni.h"
*/
import "C"
import (
	"context"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/ipc"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	wireproxyawg "github.com/artem-russkikh/wireproxy-awg"
	"github.com/wgtunnel/android/shared"
)

import "C"

var (
	cancelFuncs          map[int32]context.CancelFunc
	tag                  string
	virtualTunnelHandles map[int32]*wireproxyawg.VirtualTun
)

func init() {
	tag = "AwgProxy"
	virtualTunnelHandles = make(map[int32]*wireproxyawg.VirtualTun)
	cancelFuncs = make(map[int32]context.CancelFunc)
}

//export awgStartProxy
func awgStartProxy(interfaceName string, config string, uapiPath string, bypass int32) int32 {

	conf, err := wireproxyawg.ParseConfigString(config)
	if err != nil {
		shared.LogError(tag, "Invalid config file", err)
		return -1
	}

	handle, err := shared.GenerateUniqueHandle()
	if err != nil {
		shared.LogError(tag, "Error generating handle: %v", err)
		return -1
	}

	setting, err := wireproxyawg.CreateIPCRequest(conf.Device, false)

	if err != nil {
		shared.LogError(tag, "Create IPC request failed", err)
		return -1
	}

	tun, tnet, err := netstack.CreateNetTUN(setting.DeviceAddr, setting.DNS, setting.MTU)
	if err != nil {
		shared.LogError(tag, "Create TUN failed", err)
		return -1
	}

	name, err := tun.Name()

	var bind conn.Bind

	if bypass == 1 {
		bind = conn.NewStdNetBindWithControl(protectControlFunc)
	} else {
		bind = conn.NewStdNetBind()
	}

	statusCB := func(code device.StatusCode) {
		go C.awgNotifyStatus(C.int32_t(handle), C.int32_t(code))
	}

	dev := device.NewDevice(tun, bind, shared.NewLogger("Tun/"+interfaceName), statusCB)

	dev.DisableSomeRoamingForBrokenMobileSemantics()

	err = dev.IpcSet(setting.IpcRequest)

	if err != nil {
		shared.LogError(tag, "Ipc setting failed", err)
		return -1
	}

	uapiFile, err := ipc.UAPIOpen(uapiPath, name)

	var uapi net.Listener

	if err != nil {
		shared.LogError(tag, "UAPIOpen: %v", err)
	} else {
		uapi, err = ipc.UAPIListen(uapiPath, name, uapiFile)
		if err != nil {
			uapiFile.Close()
			shared.LogError(tag, "UAPIListen: %v", err)
		} else {
			go func() {
				for {
					connection, err := uapi.Accept()
					if err != nil {
						return
					}
					go dev.IpcHandle(connection)
				}
			}()
		}
	}

	err = dev.Up()
	if err != nil {
		shared.LogError(tag, "Failed to bring up device", err)
		uapiFile.Close()
		dev.Close()
		return -1
	}

	virtualTun := &wireproxyawg.VirtualTun{
		Tnet:           tnet,
		Dev:            dev,
		Logger:         shared.NewLogger("Proxy"),
		Uapi:           uapi,
		Conf:           conf.Device,
		PingRecord:     make(map[string]uint64),
		PingRecordLock: new(sync.Mutex),
	}

	virtualTunnelHandles[handle] = virtualTun

	// Create cancellable context
	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())
	cancelFuncs[handle] = tunnelCancel

	// Spawn all routines with context
	for _, spawner := range conf.Routines {
		shared.LogDebug(tag, "Spawning routine..")
		go func(s wireproxyawg.RoutineSpawner) {
			if err := s.SpawnRoutine(tunnelCtx, virtualTun); err != nil {
				shared.LogError(tag, "Routine failed: %v", err)
			}
		}(spawner)
	}

	shared.LogDebug(tag, "Done starting proxy and tunnel")
	return handle
}

//export awgUpdateProxyTunnelPeers
func awgUpdateProxyTunnelPeers(tunnelHandle int32, settings string) int32 {
	handle, ok := virtualTunnelHandles[tunnelHandle]
	if !ok {
		shared.LogError(tag, "Tunnel is not up")
		return -1
	}

	conf, err := wireproxyawg.ParseConfigString(settings)
	if err != nil {
		shared.LogError(tag, "Invalid config file", err)
		return -1
	}

	ipcRequest, err := wireproxyawg.CreatePeerIPCRequest(conf.Device)
	if err != nil {
		shared.LogError(tag, "CreateIPCRequest: %v", err)
		return -1
	}

	err = handle.Dev.IpcSet(ipcRequest.IpcRequest)
	if err != nil {
		shared.LogError(tag, "IpcSet: %v", err)
		return -1
	}

	shared.LogDebug(tag, "Configuration updated successfully")
	return 0
}

//export awgGetProxyConfig
func awgGetProxyConfig(tunnelHandle int32) *C.char {
	handle, ok := virtualTunnelHandles[tunnelHandle]
	if !ok {
		shared.LogError(tag, "Tunnel is not up")
		return nil
	}
	settings, err := handle.Dev.IpcGet()
	if err != nil {
		shared.LogError(tag, "Failed to get device config: %v", err)
		return nil
	}
	return C.CString(settings)
}

// control hook to bypass sockets
func protectControlFunc(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		if C.bypass_socket(C.int(fd)) == 0 {
			opErr = syscall.EACCES
			shared.LogError(tag, "Failed to protect socket FD: %d", fd)
		} else {
			shared.LogDebug(tag, "Protected socket FD: %d", fd)
		}
	})
	if err != nil {
		return err
	}
	return opErr
}

//export awgTurnProxyTunnelOff
func awgTurnProxyTunnelOff(virtualTunnelHandle int32) {
	virtualTun, ok := virtualTunnelHandles[virtualTunnelHandle]
	if !ok {
		shared.LogError(tag, "Tunnel handle %d not found", virtualTunnelHandle)
		return
	}
	shared.LogDebug(tag, "Tearing down tunnel %d", virtualTunnelHandle)

	if cancel, exists := cancelFuncs[virtualTunnelHandle]; exists {
		cancel()
		delete(cancelFuncs, virtualTunnelHandle)
		time.Sleep(50 * time.Millisecond)
	}

	// Close UAPI listener and underlying file
	if virtualTun.Uapi != nil {
		virtualTun.Uapi.Close()
	}

	if virtualTun.Dev != nil {
		virtualTun.Dev.Close()
	}

	go C.awgNotifyStatus(
		C.int32_t(virtualTunnelHandle),
		C.int32_t(shared.StatusStop),
	)

	delete(virtualTunnelHandles, virtualTunnelHandle)
	shared.ReleaseHandle(virtualTunnelHandle)
	shared.LogDebug(tag, "Tunnel %d fully closed (UAPI/Dev/Bind purged)", virtualTunnelHandle)
}
