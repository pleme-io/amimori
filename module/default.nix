# amimori home-manager module — daemon + MCP server entry
#
# Namespace: services.amimori.daemon.* / services.amimori.mcp.*
#
# The daemon runs collectors (ARP, interface, WiFi, nmap) on intervals,
# maintains state in DashMap + SQLite, and exposes a gRPC server.
# The MCP server connects to the daemon's gRPC endpoint.
#
# Module factory: receives { hmHelpers } from flake.nix, returns HM module.
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

  # ── Daemon YAML config (generated from nix options) ──────────────────
  amimoriConfig = pkgs.writeText "amimori.yaml"
    (builtins.toJSON {
      interfaces = daemonCfg.interfaces;
      grpc_port = daemonCfg.grpcPort;
      arp_interval = daemonCfg.arpInterval;
      interface_interval = daemonCfg.interfaceInterval;
      wifi_interval = daemonCfg.wifiInterval;
      scan_interval = daemonCfg.scanInterval;
      db_path = "${config.home.homeDirectory}/.local/share/amimori/state.db";
      event_buffer_size = daemonCfg.eventBufferSize;
      nmap = {
        enable = daemonCfg.nmap.enable;
        bin = "${daemonCfg.nmap.package}/bin/nmap";
        service_detection = daemonCfg.nmap.serviceDetection;
      };
    });
in {
  options.services.amimori = {
    # ── Daemon options ─────────────────────────────────────────────────
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
        default = ["en0"];
        description = "Network interfaces to monitor";
      };

      grpcPort = mkOption {
        type = types.int;
        default = 50051;
        description = "gRPC server listen port";
      };

      arpInterval = mkOption {
        type = types.int;
        default = 5;
        description = "ARP table poll interval in seconds";
      };

      interfaceInterval = mkOption {
        type = types.int;
        default = 5;
        description = "Interface state poll interval in seconds";
      };

      wifiInterval = mkOption {
        type = types.int;
        default = 15;
        description = "WiFi scan interval in seconds";
      };

      scanInterval = mkOption {
        type = types.int;
        default = 60;
        description = "nmap scan interval in seconds";
      };

      eventBufferSize = mkOption {
        type = types.int;
        default = 10000;
        description = "Number of delta events to keep in the ring buffer";
      };

      nmap = {
        enable = mkOption {
          type = types.bool;
          default = true;
          description = "Enable nmap scanning for host discovery and service detection";
        };

        package = mkOption {
          type = types.package;
          default = pkgs.nmap;
          description = "nmap package";
        };

        serviceDetection = mkOption {
          type = types.bool;
          default = false;
          description = "Enable nmap service version detection (-sV). Slower but more detail.";
        };
      };
    };

    # ── MCP options (from substrate hm-service-helpers) ───────────────
    mcp = mkMcpOptions {
      defaultPackage = pkgs.amimori;
    };
  };

  # ── Config ─────────────────────────────────────────────────────────
  config = mkMerge [
    # MCP server entry
    (mkIf mcpCfg.enable {
      services.amimori.mcp.serverEntry = mkMcpServerEntry {
        command = "${mcpCfg.package}/bin/amimori";
        env.AMIMORI_GRPC_URL = "http://localhost:${toString daemonCfg.grpcPort}";
      };
    })

    # Darwin: launchd agent for daemon
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

    # Linux: systemd service for daemon
    (mkIf (daemonCfg.enable && !isDarwin)
      (mkSystemdService {
        name = "amimori";
        description = "amimori — continuous network profiler";
        command = "${daemonCfg.package}/bin/amimori";
        args = ["daemon" "--config" "${amimoriConfig}"];
      }))
  ];
}
