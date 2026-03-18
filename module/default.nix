# amimori home-manager module — MCP server entry only
#
# The daemon runs as a system-level service (darwinModules / nixosModules).
# This HM module only configures the MCP server that queries the daemon via gRPC.
#
# Namespace: services.amimori.mcp.*
{ hmHelpers }:
{
  lib,
  config,
  pkgs,
  ...
}:
with lib; let
  inherit (hmHelpers) mkMcpOptions mkMcpServerEntry mkAnvilRegistration;
  mcpCfg = config.services.amimori.mcp;

  # gRPC connection settings — used by the MCP server to reach the daemon
  grpcCfg = config.services.amimori.grpc;
in {
  options.services.amimori = {
    grpc = {
      address = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "gRPC server address (must match daemon config)";
      };
      port = mkOption {
        type = types.int;
        default = 50051;
        description = "gRPC server port (must match daemon config)";
      };
    };

    mcp = mkMcpOptions {
      defaultPackage = pkgs.amimori;
    };
  };

  config = mkIf mcpCfg.enable (mkMerge [
    # Self-register with anvil (primary path)
    (mkAnvilRegistration {
      name = "amimori";
      command = "amimori";
      package = mcpCfg.package;
      env.AMIMORI_GRPC_URL = "http://${grpcCfg.address}:${toString grpcCfg.port}";
      description = "Network profiler and topology";
      scopes = mcpCfg.scopes;
    })

    # Deprecated: serverEntry (kept for backward compatibility)
    {
      services.amimori.mcp.serverEntry = mkMcpServerEntry {
        command = "${mcpCfg.package}/bin/amimori";
        env.AMIMORI_GRPC_URL = "http://${grpcCfg.address}:${toString grpcCfg.port}";
      };
    }
  ]);
}
