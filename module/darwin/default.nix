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
      address = mkOption { type = types.str; default = "127.0.0.1"; };
      port = mkOption { type = types.int; default = 50051; };
    };

    collectors = {
      arp = {
        enable = mkOption { type = types.bool; default = true; };
        interval = mkOption { type = types.int; default = 5; };
        maxFailures = mkOption { type = types.int; default = 10; };
      };
      interface = {
        enable = mkOption { type = types.bool; default = true; };
        interval = mkOption { type = types.int; default = 5; };
        maxFailures = mkOption { type = types.int; default = 10; };
      };
      wifi = {
        enable = mkOption { type = types.bool; default = true; description = "WiFi scanning via CoreWLAN"; };
        interval = mkOption { type = types.int; default = 15; };
        maxFailures = mkOption { type = types.int; default = 10; };
      };
      nmap = {
        enable = mkOption { type = types.bool; default = true; };
        interval = mkOption { type = types.int; default = 60; description = "Scan interval in seconds"; };
        package = mkOption { type = types.package; default = pkgs.nmap; };
        timeout = mkOption { type = types.int; default = 120; };
        serviceDetection = mkOption { type = types.bool; default = true; description = "Service version detection (-sV)"; };
        osDetection = mkOption { type = types.bool; default = true; description = "OS fingerprinting (-O). Requires root."; };
        topPorts = mkOption { type = types.int; default = 200; description = "Number of top ports to scan"; };
        versionIntensity = mkOption { type = types.int; default = 7; description = "Version detection intensity (0-9)"; };
        subnets = mkOption { type = types.listOf types.str; default = []; };
        maxFailures = mkOption { type = types.int; default = 3; };
      };
    };

    storage = {
      dbPath = mkOption {
        type = types.str;
        default = "/var/lib/amimori/state.db";
        description = "Path to SQLite database";
      };
      eventBufferSize = mkOption { type = types.int; default = 10000; };
      retention = {
        hostTtl = mkOption { type = types.int; default = 86400; };
        pruneInterval = mkOption { type = types.int; default = 300; };
      };
    };

    filters = {
      excludeMacs = mkOption { type = types.listOf types.str; default = []; };
      excludeIps = mkOption { type = types.listOf types.str; default = []; };
      excludeInterfaces = mkOption { type = types.listOf types.str; default = []; };
      includeVendors = mkOption { type = types.listOf types.str; default = []; };
    };

    logging = {
      level = mkOption { type = types.str; default = "info"; };
      format = mkOption { type = types.str; default = "text"; };
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
