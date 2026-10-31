import argparse
import json
import logging
import os
import sys
import yaml
from typing import Any, Dict, List

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class ConfigParameterCorrelationAnalyzer:
    """
    Analyzes configuration files to identify correlations between parameters
    that could lead to misconfigurations or vulnerabilities.
    """

    def __init__(self, config_file: str):
        """
        Initializes the analyzer with the configuration file path.

        Args:
            config_file (str): Path to the configuration file.
        """
        self.config_file = config_file
        self.config_data = self._load_config()
        # Only the relationships the checks below actually evaluate.
        self.parameter_relationships = {
            "timeout": ["buffer_size"],
            "buffer_size": ["max_connections"],
        }
        self.checked_parameters = {"timeout", "buffer_size", "max_connections"}

    def _load_config(self) -> Dict[str, Any]:
        """
        Loads the configuration file and returns the data as a dictionary.
        Supports YAML and JSON formats.

        Returns:
            Dict[str, Any]: The configuration data.

        Raises:
            FileNotFoundError: If the configuration file is not found.
            ValueError: If the file format is not supported.
        """
        try:
            with open(self.config_file, "r") as f:
                if self.config_file.endswith((".yaml", ".yml")):
                    try:
                        data = yaml.safe_load(f)
                        if data is None:  # Handle empty YAML files
                            return {}
                        return data
                    except yaml.YAMLError as e:
                        logging.error(f"Error parsing YAML file: {e}")
                        raise
                elif self.config_file.endswith(".json"):
                    try:
                        return json.load(f)
                    except json.JSONDecodeError as e:
                        logging.error(f"Error parsing JSON file: {e}")
                        raise
                else:
                    raise ValueError("Unsupported file format.  Must be YAML or JSON.")
        except FileNotFoundError:
            logging.error(f"Configuration file not found: {self.config_file}")
            raise
        except Exception as e:
            logging.error(f"Error loading configuration: {e}")
            raise

    def _flatten_parameters(self) -> Dict[str, Any]:
        """Collect the checked parameters from the top level and from nested mappings.

        The first occurrence of each named parameter wins. Returns a flat
        name to value dictionary.
        """
        flat: Dict[str, Any] = {}

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in self.checked_parameters and not isinstance(value, (dict, list)):
                        if key not in flat:
                            flat[key] = value
                    if isinstance(value, dict):
                        walk(value)

        walk(self.config_data)
        return flat

    def analyze_correlations(self):
        """
        Analyzes the configuration data for potential misconfigurations.

        Returns:
            tuple: (warnings, incomplete) where warnings holds the finding
            messages and incomplete holds a notice for every check that
            could not run because a related parameter was missing, plus a
            notice when none of the checked parameters are present at all.
        """
        warnings = []
        incomplete = []
        params = self._flatten_parameters()

        if not params:
            incomplete.append(
                "None of the parameters this tool checks (timeout, buffer_size, max_connections) were found in the configuration."
            )
            return warnings, incomplete

        # Check 1: timeout against buffer_size.
        if "timeout" in params and "buffer_size" in params:
            if params["timeout"] > 60 and params["buffer_size"] < 1024:
                warnings.append(
                    f"Potential denial of service vulnerability: Timeout is set to {params['timeout']} seconds, but buffer size is only {params['buffer_size']} bytes. Increase buffer size."
                )
        elif "timeout" in params or "buffer_size" in params:
            present = "timeout" if "timeout" in params else "buffer_size"
            missing = "buffer_size" if present == "timeout" else "timeout"
            incomplete.append(
                f"Check not completed: '{present}' is present but the related parameter '{missing}' was not found."
            )

        # Check 2: buffer_size against max_connections.
        if "buffer_size" in params and "max_connections" in params:
            if params["buffer_size"] > 1024 * 1024 and params["max_connections"] > 100:
                warnings.append(
                    f"High buffer size ({params['buffer_size']} bytes) with a high number of max connections ({params['max_connections']}) may lead to resource exhaustion. Limit max connections."
                )
        elif "buffer_size" in params or "max_connections" in params:
            present = "buffer_size" if "buffer_size" in params else "max_connections"
            missing = "max_connections" if present == "buffer_size" else "buffer_size"
            incomplete.append(
                f"Check not completed: '{present}' is present but the related parameter '{missing}' was not found."
            )

        return warnings, incomplete


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command line interface.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Identifies correlations between configuration parameters. Two checks run: timeout against buffer_size, and buffer_size against max_connections. Parameters are found at the top level and inside nested mappings."
    )
    parser.add_argument(
        "config_file",
        help="Path to the configuration file (YAML or JSON)",
        type=str,
        metavar="CONFIG_FILE",
    )
    return parser


def main() -> None:
    """
    Main function to execute the configuration analysis.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation
    if not os.path.isfile(args.config_file):
        logging.error(f"Error: Configuration file '{args.config_file}' not found.")
        sys.exit(1)

    try:
        analyzer = ConfigParameterCorrelationAnalyzer(args.config_file)

        if not isinstance(analyzer.config_data, dict) or not analyzer.config_data:
            logging.error(f"Configuration file '{args.config_file}' is empty or holds no mapping. Nothing to analyze.")
            sys.exit(1)

        warnings, incomplete = analyzer.analyze_correlations()

        if warnings:
            print("Potential Misconfigurations:")
            for warning in warnings:
                print(f"  - {warning}")
        if incomplete:
            print("Not Fully Checked:")
            for notice in incomplete:
                print(f"  - {notice}")
        if not warnings and not incomplete:
            print("No potential misconfigurations found.")

        if warnings or incomplete:
            sys.exit(1)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()