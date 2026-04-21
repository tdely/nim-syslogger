import std / [logging, net, parseutils, strutils, uri]

type
  Facility* = enum
    Kern     = 0,  ## Kernel messages
    User     = 1,  ## Random user-level messages
    Mail     = 2,  ## Mail system
    Daemon   = 3,  ## System daemons
    Auth     = 4,  ## Security/authorization messages
    Syslog   = 5,  ## Messages generated internally by syslogd
    Lpr      = 6,  ## Line printer subsystem
    News     = 7,  ## Network news subsystem
    Uucp     = 8,  ## UUCP subsystem
    Cron     = 9,  ## Clock daemon
    AuthPriv = 10, ## Security/authorization messages (private)
    Ftp      = 11, ## FTP daemon
    Local0   = 16, ## Reserved for local use
    Local1   = 17, ## Reserved for local use
    Local2   = 18, ## Reserved for local use
    Local3   = 19, ## Reserved for local use
    Local4   = 20, ## Reserved for local use
    Local5   = 21, ## Reserved for local use
    Local6   = 22, ## Reserved for local use
    Local7   = 23  ## Reserved for local use

  SyslogLogger* = ref object of Logger
    ## A logger that writes log messages to syslog.
    ##
    ## Create a new ``SyslogLogger`` with the `newSyslogLogger proc
    ## <#newSyslogLogger>`_.
    name: string
    address: string
    socket: Socket
    hostname: string
    facility: Facility

method log*(logger: SyslogLogger, level: Level, args: varargs[string, `$`]) =
  ## Logs to syslog with the given `SyslogLogger<#SyslogLogger>`_ only.
  ##
  ## This method ignores the list of registered handlers.
  ##
  ## Whether the message is logged depends on the SyslogLogger's
  ## ``levelThreshold`` field and the global log filter set using the
  ## `setLogFilter proc<#setLogFilter,Level>`_.
  ##   ```
  if level >= getLogFilter() and level >= logger.levelThreshold:
    let priority = (ord(logger.facility) * 8) + ord(level)
    let ln = substituteLog(logger.fmtStr, level, args)
    logger.socket.send("<$1>$2: $3" % [$priority, logger.name, ln])

proc newSyslogLogger*(name, address: string, levelThreshold = lvlAll, fmtStr = defaultFmtStr, facility = User): SyslogLogger =
  ## Creates a new `SyslogLogger<#SyslogLogger>`_.
  new result
  result.fmtStr = fmtStr
  result.levelThreshold = levelThreshold
  result.name = name
  result.facility = facility
  var uri = parseUri(address)
  case uri.scheme:
  of "ipc":
    result.socket = newSocket(AF_UNIX, SOCK_DGRAM, IPPROTO_IP)
    result.socket.connectUnix(uri.path)
    return
  of "tcp":
    result.socket = newSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
  of "udp":
    result.socket = newSocket(AF_UNIX, SOCK_DGRAM, IPPROTO_UDP)
  else:
    raise newException(ValueError, "Invalid or missing scheme")
  if uri.hostname.len == 0:
    raise newException(ValueError, "No hostname given in address")
  elif uri.port.len == 0:
    raise newException(ValueError, "No port given in address")
  var port: int
  if parseInt(uri.port, port) == 0 or port < 1 or port > 65535:
    raise newException(ValueError, "Invalid port: " & $port)
  result.socket.connect(uri.hostname, Port(port))
