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
		shared.ReleaseHandle(handle)
		return -1
	}

	tun, tnet, err := netstack.CreateNetTUN(setting.DeviceAddr, setting.DNS, setting.MTU)
	if err != nil {
		shared.LogError(tag, "Create TUN failed", err)
		shared.ReleaseHandle(handle)
		return -1
	}

	name, err := tun.Name()
	if err != nil {
		shared.LogError(tag, "Failed to get TUN name: %v", err)
		shared.ReleaseHandle(handle)
		tun.Close()
		return -1
	}

	// Lockdown modes needs our socket protection
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
		shared.ReleaseHandle(handle)
		dev.Close()
		return -1
	}

	var uapi net.Listener
	uapiFile, uapiErr := ipc.UAPIOpen(uapiPath, name)
	if uapiErr != nil {
		shared.LogError(tag, "UAPIOpen: %v", uapiErr)
		uapiFile = nil
	} else {
		uapi, err = ipc.UAPIListen(uapiPath, name, uapiFile)
		if err != nil {
			shared.LogError(tag, "UAPIListen: %v", err)
			uapiFile.Close()
			uapiFile = nil
			uapi = nil
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
		if uapiFile != nil {
			uapiFile.Close()
		}
		if uapi != nil {
			uapi.Close()
		}
		shared.ReleaseHandle(handle)
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

	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())
	cancelFuncs[handle] = tunnelCancel

	for _, spawner := range conf.Routines {
		go func(s wireproxyawg.RoutineSpawner) {
			if err := s.SpawnRoutine(tunnelCtx, virtualTun); err != nil {
				shared.LogError(tag, "Routine failed: %v", err)
			}
		}(spawner)
	}

	shared.LogDebug(tag, "Done starting proxy and tunnel for handle %d", handle)
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

	delete(virtualTunnelHandles, virtualTunnelHandle)

	if cancel, exists := cancelFuncs[virtualTunnelHandle]; exists {
		cancel()
		delete(cancelFuncs, virtualTunnelHandle)
	}

	if virtualTun.Uapi != nil {
		virtualTun.Uapi.Close()
	}
	if virtualTun.Dev != nil {
		virtualTun.Dev.Close()
	}

	C.awgNotifyStatus(
		C.int32_t(virtualTunnelHandle),
		C.int32_t(shared.StatusStop),
	)

	// Give time for full resource release
	time.Sleep(150 * time.Millisecond)

	shared.ReleaseHandle(virtualTunnelHandle)

	shared.LogDebug(tag, "Tunnel handle %d fully closed", virtualTunnelHandle)
}
