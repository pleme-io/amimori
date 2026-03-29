# amimori nix-darwin module — launchd service
#
# Namespace: services.amimori.*
#
# Enables amimori as a system-level launchd service on macOS via nix-darwin.
# For home-manager integration, use homeManagerModules.default instead.
{ lib, config, pkgs, ... }:

with lib; let
  cfg = config.services.amimori;

  amimoriConfig = pkgs.writeText "amimori.yaml"
    (builtins.toJSON {
      interfaces = cfg.interfaces;
      grpc = {
        address = cfg.grpc.address;
        port = cfg.grpc.port;
      };
      collectors = {
        arp = {
          enable = cfg.collectors.arp.enable;
          interval = cfg.collectors.arp.interval;
          max_failures = cfg.collectors.arp.maxFailures;
        };
        interface = {
          enable = cfg.collectors.interface.enable;
          interval = cfg.collectors.interface.interval;
          max_failures = cfg.collectors.interface.maxFailures;
        };
        wifi = {
          enable = cfg.collectors.wifi.enable;
          interval = cfg.collectors.wifi.interval;
          max_failures = cfg.collectors.wifi.maxFailures;
        };
        nmap = {
          enable = cfg.collectors.nmap.enable;
          interval = cfg.collectors.nmap.interval;
          bin = "${cfg.collectors.nmap.package}/bin/nmap";
          timeout = cfg.collectors.nmap.timeout;
          service_detection = cfg.collectors.nmap.serviceDetection;
          os_detection = cfg.collectors.nmap.osDetection;
          top_ports = cfg.collectors.nmap.topPorts;
          version_intensity = cfg.collectors.nmap.versionIntensity;
          subnets = cfg.collectors.nmap.subnets;
          max_failures = cfg.collectors.nmap.maxFailures;
        };
      };
      storage = {
        db_path = cfg.storage.dbPath;
        event_buffer_size = cfg.storage.eventBufferSize;
        retention = {
          host_ttl = cfg.storage.retention.hostTtl;
          prune_interval = cfg.storage.retention.pruneInterval;
        };
      };
      filters = {
        exclude_macs = cfg.filters.excludeMacs;
        exclude_ips = cfg.filters.excludeIps;
        exclude_interfaces = cfg.filters.excludeInterfaces;
        include_vendors = cfg.filters.includeVendors;
      };
      logging = {
        level = cfg.logging.level;
        format = cfg.logging.format;
      };
    });
in {
  options.services.amimori = {
    enable = mkEnableOption "amimori continuous network profiler";

    package = mkOption {
      type = types.package;
      default = pkgs.amimori;
      description = "amimori package";
    };

    interfaces = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Network interfaces to monitor. Empty = auto-detect.";
    };

    grpc = {
      address = mkOption { type = types.str; default = "127.0.0.1"; description = "gRPC listen address for MCP queries."; };
      port = mkOption { type = types.int; default = 50051; description = "gRPC listen port for MCP queries."; };
    };

    collectors = {
      arp = {
        enable = mkOption { type = types.bool; default = true; description = "Enable ARP table polling for host discovery."; };
        interval = mkOption { type = types.int; default = 5; description = "ARP poll interval in seconds."; };
        maxFailures = mkOption { type = types.int; default = 10; description = "Consecutive failures before disabling ARP collector."; };
      };
      interface = {
        enable = mkOption { type = types.bool; default = true; description = "Enable network interface monitoring."; };
        interval = mkOption { type = types.int; default = 5; description = "Interface poll interval in seconds."; };
        maxFailures = mkOption { type = types.int; default = 10; description = "Consecutive failures before disabling interface collector."; };
      };
      wifi = {
        enable = mkOption { type = types.bool; default = true; description = "Enable WiFi scanning via CoreWLAN."; };
        interval = mkOption { type = types.int; default = 15; description = "WiFi scan interval in seconds."; };
        maxFailures = mkOption { type = types.int; default = 10; description = "Consecutive failures before disabling WiFi collector."; };
      };
      nmap = {
        enable = mkOption { type = types.bool; default = true; description = "Enable nmap-based service discovery."; };
        interval = mkOption { type = types.int; default = 60; description = "Nmap scan interval in seconds."; };
        package = mkOption { type = types.package; default = pkgs.nmap; description = "Nmap package to use."; };
        timeout = mkOption { type = types.int; default = 120; description = "Per-scan timeout in seconds."; };
        serviceDetection = mkOption { type = types.bool; default = true; description = "Service version detection (-sV)."; };
        osDetection = mkOption { type = types.bool; default = true; description = "OS fingerprinting (-O). Requires root."; };
        topPorts = mkOption { type = types.int; default = 200; description = "Number of top ports to scan."; };
        versionIntensity = mkOption { type = types.int; default = 7; description = "Version detection intensity (0-9)."; };
        subnets = mkOption { type = types.listOf types.str; default = []; description = "Subnets to scan. Empty = auto-detect from interfaces."; };
        maxFailures = mkOption { type = types.int; default = 3; description = "Consecutive failures before disabling nmap collector."; };
      };
    };

    storage = {
      dbPath = mkOption {
        type = types.str;
        default = "/var/lib/amimori/state.db";
        description = "Path to SQLite database for host/event storage.";
      };
      eventBufferSize = mkOption { type = types.int; default = 10000; description = "Maximum events buffered before flush."; };
      retention = {
        hostTtl = mkOption { type = types.int; default = 86400; description = "Host TTL in seconds before pruning (default: 24h)."; };
        pruneInterval = mkOption { type = types.int; default = 300; description = "Interval between prune cycles in seconds (default: 5min)."; };
      };
    };

    filters = {
      excludeMacs = mkOption { type = types.listOf types.str; default = []; description = "MAC addresses to exclude from monitoring."; };
      excludeIps = mkOption { type = types.listOf types.str; default = []; description = "IP addresses to exclude from monitoring."; };
      excludeInterfaces = mkOption { type = types.listOf types.str; default = []; description = "Network interfaces to exclude from monitoring."; };
      includeVendors = mkOption { type = types.listOf types.str; default = []; description = "Vendor prefixes to include (empty = all vendors)."; };
    };

    logging = {
      level = mkOption { type = types.str; default = "info"; description = "Log level (trace, debug, info, warn, error)."; };
      format = mkOption { type = types.str; default = "text"; description = "Log format (text or json)."; };
    };
  };

  config = mkIf cfg.enable {
    launchd.daemons.amimori = {
      serviceConfig = {
        Label = "io.pleme.amimori";
        ProgramArguments = [
          "${cfg.package}/bin/amimori"
          "daemon"
          "--config"
          "${amimoriConfig}"
        ];
        RunAtLoad = true;
        KeepAlive = true;
        ProcessType = "Adaptive";
        StandardOutPath = "/var/log/amimori.log";
        StandardErrorPath = "/var/log/amimori.log";
        EnvironmentVariables = {
          PATH = lib.makeBinPath (
            [ cfg.package ]
            ++ lib.optional cfg.collectors.nmap.enable cfg.collectors.nmap.package
          );
        };
      };
    };
  };
}
