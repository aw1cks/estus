# Home Manager module for Estus; exported as `homeModules.default` by flake.nix.
# `self` is this flake, the default source of `programs.estus.package`.
self:
{ config, lib, pkgs, ... }:
let
  cfg = config.programs.estus;
  tomlFormat = pkgs.formats.toml { };

  # Estus takes the config file by absolute path and never searches for one.
  configPath = "${config.xdg.configHome}/estus/estus.toml";

  # Fail the build, not the MCP client's startup, on a config Estus rejects.
  # `auth explain` loads and validates the whole file offline, so it needs a
  # declared target to run against. Loading also checks that configured file
  # paths exist, which they may not inside the build sandbox.
  generated = tomlFormat.generate "estus.toml" cfg.settings;
  targets = lib.attrNames (cfg.settings.targets or { });
  configFile =
    if !cfg.validate || targets == [ ] then
      generated
    else
      pkgs.runCommand "estus.toml" { nativeBuildInputs = [ cfg.package ]; } ''
        cp ${generated} estus.toml
        estus --config estus.toml auth explain ${lib.escapeShellArg (lib.head targets)} > /dev/null
        cp estus.toml "$out"
      '';
in
{
  options.programs.estus = {
    enable = lib.mkEnableOption "Estus, an MCP server for policy-gated operations over SSH";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "estus.packages.\${pkgs.stdenv.hostPlatform.system}.default";
      example = lib.literalExpression "estus.packages.\${pkgs.stdenv.hostPlatform.system}.automation";
      description = ''
        The Estus package. It includes the tool catalog. Use the `automation`
        package for a build that also ships an Ansible bundle.

        The package puts its own OpenSSH first on `PATH`. To use a different
        `ssh`, for example Apple's on macOS for Keychain support, set
        `settings.ssh.executable`.
      '';
    };

    settings = lib.mkOption {
      type = tomlFormat.type;
      default = { };
      example = lib.literalExpression ''
        {
          capabilities = { named = true; file_read = true; };
          selection.presets = [ "linux-health" ];
          targets.web-1.ssh_host = "web-1";
          automation.targets.web-1 = {
            destination = "web-1";
            python = "/usr/bin/python3";
          };
        }
      '';
      description = ''
        Contents of {file}`$XDG_CONFIG_HOME/estus/estus.toml`. See
        <https://github.com/aw1cks/estus/blob/main/docs/configuration.md>
        for every key. Unknown keys fail the build when at least one target is
        declared. Estus does not expand `~` or environment variables, so use
        absolute paths.
      '';
    };

    mcp.enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to add Estus to {option}`programs.mcp.servers` and turn on
        {option}`programs.mcp`. Each client then picks it up through its own
        `enableMcpIntegration`, for example
        {option}`programs.claude-code.enableMcpIntegration`.
      '';
    };

    validate = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to load {option}`settings` with Estus at build time, so a
        rejected config fails `home-manager switch` instead of the MCP client's
        startup. Only runs when `settings.targets` declares a target. Estus also
        checks that files named in the config exist, so turn this off if
        {option}`settings` names a file outside the Nix store, such as
        `ssh.config_file`, that the build sandbox cannot see.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    xdg.configFile."estus/estus.toml".source = configFile;

    programs.mcp = lib.mkIf cfg.mcp.enable {
      enable = lib.mkDefault true;
      servers.estus = {
        command = "${cfg.package}/bin/estus";
        args = [ "--config" configPath ];
      };
    };
  };
}
