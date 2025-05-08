import pcap
import streams
import strutils, sequtils
import os
import unittest

type

  ProtocolType = enum
    NONE, v4, v6, TCP, UDP

  Protocol = object
    portSRC: int
    portDST: int
    length: int
    checksum: string
    payload: string

  Ethernet = object
    macDST: string
    macSRC: string
    protocol: ProtocolType
  
  IPv4 = object
    version: int
    headerLength: int
    service: int
    totalLength: int
    identification: string
    flags: string
    ttl: int
    protocol: ProtocolType
    checksum: string
    srcIP: string
    dstIP: string

proc getEthernet(data: var seq[string]): Ethernet =
  result.macDST = data[0..5].join(":")
  result.macSRC = data[6..11].join(":")
  case data[12..13].join(""):
    of "0800": result.protocol = v4
    of "86dd": result.protocol = v6
    of "0806": result.protocol = TCP
    of "0801": result.protocol = UDP
  data = data[14..^1]

proc getIP(data: var seq[string]): IPv4 =
  result.version = ($data[0][0]).parseInt
  result.headerLength = ($data[0][1]).parseInt  * 4
  result.service = data[1].parseHexInt #Если использовать parseInt, то не проходит несколько тестов
  result.totalLength = data[2..3].join("").parseHexInt
  result.identification = data[4..5].join("")
  result.flags = data[6..7].join("")
  result.ttl = data[8].parseHexInt
  result.protocol = case data[9]:
    of "06": TCP
    of "17": UDP
    else: NONE
  result.checksum = data[10..11].join("")
  result.srcIP = data[12..15].mapIt(it.parseHexInt).join(".")
  result.dstIP = data[16..19].mapIt(it.parseHexInt).join(".")
  data = data[20..^1]

proc getUDP(data: var seq[string]): Protocol =
  result.portSRC = data[0..1].join.parseHexInt
  result.portDST = data[2..3].join.parseHexInt
  result.length = data[4..5].join.parseHexInt
  result.checksum = data[6..7].join
  result.payload = data[8..^1].join.toLower
  data = @[]

proc getTCP(data: var seq[string]): Protocol =
  result.portSRC = data[0..1].join.parseHexInt
  result.portDST = data[2..3].join.parseHexInt
  result.length = ($data[12][0]).parseHexInt * 4
  result.checksum = data[16..17].join
  result.payload = data[result.length..^1].join.toLower
  data = @[]

proc test1() =
  suite "example_1":
    let s = newFileStream(getAppDir() / "example_1.pcap")
    var gh = s.readGlobalHeader
    while not s.atEnd:
      var
        e: Ethernet
        ip: IPv4
        p: Protocol
      setup:
        let h = s.readRecordHeader(gh)
        var r = s.readRecord(h).data.mapIt(it.toHex)
        e = r.getEthernet
        ip = r.getIP
        p = case ip.protocol:
          of UDP: r.getUDP
          of TCP: r.getTCP
          else: Protocol()
      test "getPackage":
        check e.macDST != ""
        check e.macSRC != ""
        if ip.protocol != NONE:
          check ip.version != 0
          check ip.ttl != 0
          check ip.srcIP != ""
          check ip.dstIP != ""
        if ip.protocol != NONE:
          check p.portDST != 0
          check p.length != 0
    s.close()

proc test2() =
  suite "example_2":
    let s = newFileStream(getAppDir() / "example_2.pcap")
    var gh = s.readGlobalHeader
    while not s.atEnd:
      var
        e: Ethernet
        ip: IPv4
        p: Protocol
      setup:
        let h = s.readRecordHeader(gh)
        var r = s.readRecord(h).data.mapIt(it.toHex)
        e = r.getEthernet
        ip = r.getIP
        p = case ip.protocol:
          of UDP: r.getUDP
          of TCP: r.getTCP
          else: Protocol()
      test "getPackage":
        check e.macDST != ""
        check e.macSRC != ""
        if ip.protocol != NONE:
          check ip.version != 0
          check ip.ttl != 0
          check ip.srcIP != ""
          check ip.dstIP != ""
        if ip.protocol != NONE:
          check p.portDST != 0
          check p.length != 0
    s.close()

when isMainModule:
  test1()
  test2()
