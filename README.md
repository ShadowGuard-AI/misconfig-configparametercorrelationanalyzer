![Banner](banner.png)

# misconfig-ConfigParameterCorrelationAnalyzer
Identifies correlations between different configuration parameters that could lead to unintended behavior or security vulnerabilities. Two checks run: a timeout above 60 seconds with a buffer_size below 1024 bytes, and a buffer_size above 1048576 bytes with max_connections above 100. The parameters timeout, buffer_size, and max_connections are looked up at the top level and inside nested mappings. No documentation cross referencing is performed. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

## Install
`git clone https://github.com/ShadowStrikeHQ/misconfig-configparametercorrelationanalyzer`

## Usage
`python3 main.py config.yaml`

## Parameters
- `config_file`: Path to the configuration file (YAML or JSON, positional, required).
- `-h`: Show help message and exit

A run exits 1 when a check produces a warning, and also when a check could not run because a related parameter was missing, when none of the checked parameters are present, or when the configuration is empty, because the analysis was not fully performed in those cases. A fully checked run with no warnings exits 0.

## License
Copyright (c) ShadowStrikeHQ
