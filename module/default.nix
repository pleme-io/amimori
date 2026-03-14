# amimori home-manager module — daemon + MCP server entry
#
# Namespace: services.amimori.daemon.* / services.amimori.mcp.*
{ hmHelpers }:
{
  lib,
  config,
  pkgs,
  ...
}:
with lib; let
  inherit (hmHelpers) mkMcpOptions mkMcpServerEntry mkLaunchdService mkSystemdService;
  daemonCfg = config.services.amimori.daemon;
  mcpCfg = config.services.amimori.mcp;
  isDarwin = pkgs.stdenv.isDarwin;

  logDir = if isDarwin
    then "${config.home.homeDirectory}/Library/Logs"
    else "${config.home.homeDirectory}/.local/share/amimori/logs";

  amimoriConfig = pkgs.writeText "amimori.yaml"
    (builtins.toJSON {
      interfaces = daemonCfg.interfaces;
      grpc = {
        address = daemonCfg.grpc.address;
        port = daemonCfg.grpc.port;
      };
      collectors = {
        arp = {
          enable = daemonCfg.collectors.arp.enable;
          interval = daemonCfg.collectors.arp.interval;
          max_failures = daemonCfg.collectors.arp.maxFailures;
        };
        interface = {
          enable = daemonCfg.collectors.interface.enable;
          interval = daemonCfg.collectors.interface.interval;
          max_failures = daemonCfg.collectors.interface.maxFailures;
        };
        wifi = {
          enable = daemonCfg.collectors.wifi.enable;
          interval = daemonCfg.collectors.wifi.interval;
          max_failures = daemonCfg.collectors.wifi.maxFailures;
        };
        nmap = {
          enable = daemonCfg.collectors.nmap.enable;
          interval = daemonCfg.collectors.nmap.interval;
          bin = "${daemonCfg.collectors.nmap.package}/bin/nmap";
          timeout = daemonCfg.collectors.nmap.timeout;
          service_detection = daemonCfg.collectors.nmap.serviceDetection;
          subnets = daemonCfg.collectors.nmap.subnets;
          max_failures = daemonCfg.collectors.nmap.maxFailures;
        };
      };
      storage = {
        db_path = "${config.home.homeDirectory}/.local/share/amimori/state.db";
        event_buffer_size = daemonCfg.storage.eventBufferSize;
        retention = {
          host_ttl = daemonCfg.storage.retention.hostTtl;
          prune_interval = daemonCfg.storage.retention.pruneInterval;
        };
      };
      filters = {
        exclude_macs = daemonCfg.filters.excludeMacs;
        exclude_ips = daemonCfg.filters.excludeIps;
        exclude_interfaces = daemonCfg.filters.excludeInterfaces;
        include_vendors = daemonCfg.filters.includeVendors;
      };
      logging = {
        level = daemonCfg.logging.level;
        format = daemonCfg.logging.format;
      };
    });
in {
  options.services.amimori = {
    daemon = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable amimori continuous network profiler daemon";
      };

      package = mkOption {
        type = types.package;
        default = pkgs.amimori;
        description = "amimori package";
      };

      interfaces = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Network interfaces to monitor. Empty = auto-detect all non-loopback.";
      };

      # ── gRPC ───────────────────────────────────────────────────────
      grpc = {
        address = mkOption {
          type = types.str;
          default = "127.0.0.1";
          description = "gRPC server bind address";
        };
        port = mkOption {
          type = types.int;
          default = 50051;
          description = "gRPC server listen port";
        };
      };

      # ── Collectors ─────────────────────────────────────────────────
      collectors = {
        arp = {
          enable = mkOption { type = types.bool; default = true; description = "Enable ARP table polling"; };
          interval = mkOption { type = types.int; default = 5; description = "ARP poll interval (seconds)"; };
          maxFailures = mkOption { type = types.int; default = 10; description = "Max consecutive failures before disabling"; };
        };
        interface = {
          enable = mkOption { type = types.bool; default = true; description = "Enable interface state polling"; };
          interval = mkOption { type = types.int; default = 5; description = "Interface poll interval (seconds)"; };
          maxFailures = mkOption { type = types.int; default = 10; };
        };
        wifi = {
          enable = mkOption { type = types.bool; default = true; description = "Enable WiFi scanning (macOS CoreWLAN)"; };
          interval = mkOption { type = types.int; default = 15; description = "WiFi scan interval (seconds)"; };
          maxFailures = mkOption { type = types.int; default = 10; };
        };
        nmap = {
          enable = mkOption { type = types.bool; default = true; description = "Enable nmap host discovery"; };
          interval = mkOption { type = types.int; default = 60; description = "nmap scan interval (seconds)"; };
          package = mkOption { type = types.package; default = pkgs.nmap; description = "nmap package"; };
          timeout = mkOption { type = types.int; default = 120; description = "nmap command timeout (seconds)"; };
          serviceDetection = mkOption { type = types.bool; default = false; description = "Enable nmap -sV service detection"; };
          subnets = mkOption { type = types.listOf types.str; default = []; description = "Subnets to scan. Empty = auto-derive from interfaces."; };
          maxFailures = mkOption { type = types.int; default = 3; };
        };
      };

      # ── Storage ────────────────────────────────────────────────────
      storage = {
        eventBufferSize = mkOption {
          type = types.int;
          default = 10000;
          description = "In-memory event ring buffer capacity";
        };
        retention = {
          hostTtl = mkOption {
            type = types.int;
            default = 86400;
            description = "Remove hosts not seen for this many seconds (0 = keep forever)";
          };
          pruneInterval = mkOption {
            type = types.int;
            default = 300;
            description = "How often to prune stale hosts (seconds)";
          };
        };
      };

      # ── Filters ────────────────────────────────────────────────────
      filters = {
        excludeMacs = mkOption { type = types.listOf types.str; default = []; description = "MAC addresses to exclude"; };
        excludeIps = mkOption { type = types.listOf types.str; default = []; description = "IP addresses to exclude"; };
        excludeInterfaces = mkOption { type = types.listOf types.str; default = []; description = "Interface names to ignore"; };
        includeVendors = mkOption { type = types.listOf types.str; default = []; description = "Only track hosts from these vendors (empty = all)"; };
      };

      # ── Logging ────────────────────────────────────────────────────
      logging = {
        level = mkOption { type = types.str; default = "info"; description = "Log level: trace, debug, info, warn, error"; };
        format = mkOption { type = types.str; default = "text"; description = "Log format: text or json"; };
      };
    };

    mcp = mkMcpOptions {
      defaultPackage = pkgs.amimori;
    };
  };

  config = mkMerge [
    (mkIf mcpCfg.enable {
      services.amimori.mcp.serverEntry = mkMcpServerEntry {
        command = "${mcpCfg.package}/bin/amimori";
        env.AMIMORI_GRPC_URL = "http://${daemonCfg.grpc.address}:${toString daemonCfg.grpc.port}";
      };
    })

    (mkIf (daemonCfg.enable && isDarwin) (mkMerge [
      {
        home.activation.amimori-dirs = lib.hm.dag.entryAfter ["writeBoundary"] ''
          run mkdir -p "${config.home.homeDirectory}/.local/share/amimori"
        '';
      }
      (mkLaunchdService {
        name = "amimori";
        label = "io.pleme.amimori";
        command = "${daemonCfg.package}/bin/amimori";
        args = ["daemon" "--config" "${amimoriConfig}"];
        logDir = logDir;
      })
    ]))

    (mkIf (daemonCfg.enable && !isDarwin)
      (mkSystemdService {
        name = "amimori";
        description = "amimori — continuous network profiler";
        command = "${daemonCfg.package}/bin/amimori";
        args = ["daemon" "--config" "${amimoriConfig}"];
      }))
  ];
}
