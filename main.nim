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
  ## Реализуйте обработку Ethernet-уровня
  ## Можно взять заготовку из лекции
  # реализуйте код тут
  data = data[14..^1]

proc getIP(data: var seq[string]): IPv4 =
  ## Реализуйте обработку IP-уровня
  ## Можно взять заготовку из лекции
  # реализуйте код тут
  data = data[20..^1]

proc getUDP(data: var seq[string]): Protocol =
  ## Реализуйте обработку протокола UDP
  ## Можно взять заготовку из лекции
  ## Учтите, полезной нагрузки может не быть.
  # реализуйте код тут
  data = @[]

proc getTCP(data: var seq[string]): Protocol =
  ## Реализуйте самостоятельно.
  ## Согласно RFC:
  ## 
  ## - порт источника: первые 2 байта
  ## - порт назначения: вторые 2 байта
  ## - размер пакета: половина 13 байта * 4
  ## - сумма: 17 и 18 байт
  ## - полезная нагрузка это размер пакета + 1 в одну строку и до конца в нижнем регистре
  ## 
  ## Учтите, полезной нагрузки может не быть.
  # реализуйте код тут
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
