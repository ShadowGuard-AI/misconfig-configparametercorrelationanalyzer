# misconfig-ConfigParameterCorrelationAnalyzer
Identifies correlations between different configuration parameters that could lead to unintended behavior or security vulnerabilities.  For example, checks if increasing a timeout parameter without increasing a related buffer size creates a denial of service vulnerability.  Uses static analysis to identify related parameters and cross-references documentation. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

## Install
`git clone https://github.com/ShadowStrikeHQ/misconfig-configparametercorrelationanalyzer`

## Usage
`./misconfig-configparametercorrelationanalyzer [params]`

## Parameters
- `-h`: Show help message and exit

## License
Copyright (c) ShadowStrikeHQ
