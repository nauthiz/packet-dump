package main

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/urfave/cli"
	"log"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"
)

type PacketInfo struct {
	Timestamp          time.Time
	TransportLayerType gopacket.LayerType
	Source             string
	Destination        string
	Payload            []byte
}

func getDervice(name string) (pcap.Interface, error) {
	devices, e := pcap.FindAllDevs()

	if e != nil {
		return pcap.Interface{}, e
	}

	for _, device := range devices {
		if device.Name == name {
			return device, nil
		}
	}

	return pcap.Interface{}, fmt.Errorf("\"%s\" device does not exist", name)
}

func capturePackets(device pcap.Interface, timeout time.Duration, filter string) error {
	var snapshotLength int32 = 1518
	var promiscuous bool = false

	handle, e := pcap.OpenLive(device.Name, snapshotLength, promiscuous, timeout)

	if e != nil {
		return e
	}

	defer handle.Close()

	e = handle.SetBPFFilter(filter)

	if e != nil {
		return e
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		packetInfo, ok := extractPacketInfo(packet)

		if !ok {
			continue
		}

		printPacketInfo(packetInfo)
	}

	return nil
}

func extractPacketInfo(packet gopacket.Packet) (PacketInfo, bool) {
	networkLayer := packet.NetworkLayer()

	if networkLayer == nil {
		return PacketInfo{}, false
	}

	layerType := networkLayer.LayerType()

	if layerType != layers.LayerTypeIPv4 && layerType != layers.LayerTypeIPv6 {
		return PacketInfo{}, false
	}

	transportLayer := packet.TransportLayer()

	if transportLayer == nil {
		return PacketInfo{}, false
	}

	layerType = transportLayer.LayerType()

	if layerType != layers.LayerTypeTCP && layerType != layers.LayerTypeUDP {
		return PacketInfo{}, false
	}

	appLayer := packet.ApplicationLayer()

	if appLayer == nil {
		return PacketInfo{}, false
	}

	networkFlow := networkLayer.NetworkFlow()
	transportFlow := transportLayer.TransportFlow()

	info := PacketInfo{
		Timestamp:          packet.Metadata().Timestamp,
		TransportLayerType: transportLayer.LayerType(),
		Source:             fmt.Sprintf("%s:%s", networkFlow.Src(), transportFlow.Src()),
		Destination:        fmt.Sprintf("%s:%s", networkFlow.Dst(), transportFlow.Dst()),
		Payload:            appLayer.Payload()}

	return info, true
}

func printPacketInfo(info PacketInfo) {
	timestamp := info.Timestamp.Format(time.RFC3339Nano)

	headerColor := color.New(color.FgGreen, color.Bold)
	headerColor.Printf("--------------------------------------------------------------------------------\n")
	headerColor.Printf("%s %s -> %s (%d bytes) %s\n", info.TransportLayerType, info.Source, info.Destination, len(info.Payload), timestamp)
	headerColor.Printf("--------------------------------------------------------------------------------\n")

	printPayload(info.Payload)
}

func printPayload(payload []byte) {
	for _, b := range payload {
		r := rune(b)

		if unicode.IsPrint(r) {
			fmt.Printf("%c", b)
		} else if r == '\n' {
			fmt.Print("\n")
		} else {
			printHex(r)
		}
	}

	fmt.Print("\n")
}

var hexColor = color.New(color.FgCyan)

func printHex(r rune) {
	hexColor.Printf("<%02x>", r)
}

func printDevices() error {
	devices, e := pcap.FindAllDevs()

	if e != nil {
		return e
	}

	sort.Slice(devices, func(i int, j int) bool {
		return strings.Compare(devices[i].Name, devices[j].Name) < 0
	})

	fmt.Printf("Devices:\n")

	for _, device := range devices {
		if len(device.Addresses) == 0 {
			continue
		}

		ips := make([]string, len(device.Addresses))

		for i, address := range device.Addresses {
			ips[i] = address.IP.String()
		}

		fmt.Printf("  %s  %s\n", device.Name, strings.Join(ips, ", "))
	}

	return nil
}

func generateFilter(c *cli.Context) (string, error) {
	conditions := []string{}

	filter := c.String("filter")
	filter = strings.TrimSpace(filter)

	if len(filter) > 0 {
		conditions = append(conditions, filter)
	}

	ports := c.IntSlice("port")

	if len(ports) > 0 {
		port := ports[len(ports)-1]
		conditions = append(conditions, fmt.Sprintf("port %d", port))
	}

	return strings.Join(conditions, " and "), nil
}

func main() {
	app := cli.NewApp()
	app.Name = "packet-dump"
	app.Usage = "Packet dump program using BPF."
	app.UsageText = `packet-dump [OPTIONS] DEVICE

   DEVICE  Specify name of network device to capture packets. eg) en0, lo0`

	app.Version = "0.1.0"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "filter, f",
			Value: "",
			Usage: "Specify packet filter expression (BPF format).",
		},
		cli.IntSliceFlag{
			Name:  "port, p",
			Usage: "Specify filtering port.",
		},
		cli.BoolFlag{
			Name:  "devices, d",
			Usage: "Print available devices.",
		},
	}
	app.Action = func(c *cli.Context) error {
		if c.Bool("devices") {
			return printDevices()
		}

		args := c.Args()

		if len(args) != 1 {
			log.Printf("ERROR: Only one argument is accepted. But actually %s", args)
			os.Exit(1)
		}

		deviceName := args[0]
		device, e := getDervice(deviceName)

		if e != nil {
			return e
		}

		filter, e := generateFilter(c)

		if e != nil {
			return e
		}

		var timeout time.Duration = 30 * time.Second

		log.Printf("INFO: Device: %s", device.Name)
		log.Printf("INFO: Filter: %s", filter)
		return capturePackets(device, timeout, filter)
	}

	e := app.Run(os.Args)

	if e != nil {
		log.Fatalf("ERROR: %s", e)
	}
}
