"""
SBOM Risk Analyzer - Data Loader Module

This module provides utility functions and classes to load and validate all files
comprising the SBOM dataset:
- applications.json
- sbom_dependencies.csv
- vulnerability_db.json
- license_rules.json
- dependency_labels.csv

Utilizes pandas for CSV files, the built-in json module for JSON files,
and incorporates robust validation for schema, missing values, duplicates,
and file integrity.
"""

import json
import logging
import os
from typing import Any, Dict, List, Tuple

import pandas as pd

# Setup Logger
logger = logging.getLogger("SBOMDataLoader")
logger.setLevel(logging.INFO)

# Formatter and Handler (if not already set up)
if not logger.handlers:
    ch = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)


class DataLoaderError(Exception):
    """Base exception for all errors occurring during data loading and validation."""
    pass


class ValidationError(DataLoaderError):
    """Exception raised when dataset files fail schema, uniqueness, or completeness checks."""
    pass


def validate_file_path(file_path: str) -> None:
    """
    Validates that the file exists and is not empty.

    Args:
        file_path: The absolute or relative path to the file.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValidationError: If the file is empty (size is 0).
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found at: {file_path}")
    if os.path.getsize(file_path) == 0:
        raise ValidationError(f"File at {file_path} is empty (0 bytes).")


def load_applications(file_path: str) -> List[Dict[str, Any]]:
    """
    Loads applications.json and validates its structure and contents.

    Args:
        file_path: Path to applications.json.

    Returns:
        A list of application dictionaries.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValidationError: If validation fails (missing fields, empty fields, duplicates).
        DataLoaderError: If JSON decoding fails.
    """
    logger.info(f"Loading applications from: {file_path}")
    validate_file_path(file_path)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise DataLoaderError(f"Failed to parse JSON file {file_path}: {e}") from e

    if not isinstance(data, list):
        raise ValidationError("applications.json must contain a JSON array/list at the root.")

    required_fields = {
        "app_id", "app_name", "owner", "business_unit",
        "business_criticality", "technology_stack", "environment", "last_scan_date"
    }

    seen_app_ids = set()

    for idx, app in enumerate(data):
        if not isinstance(app, dict):
            raise ValidationError(f"Application record at index {idx} is not a JSON object.")

        # Check required fields presence
        missing_fields = required_fields - app.keys()
        if missing_fields:
            raise ValidationError(
                f"Application record at index {idx} is missing required fields: {missing_fields}"
            )

        # Check for empty values or nulls in critical string fields
        for field in required_fields:
            val = app[field]
            if field == "technology_stack":
                if not isinstance(val, list):
                    raise ValidationError(
                        f"Field 'technology_stack' in application {app.get('app_id', idx)} must be a list."
                    )
            else:
                if val is None or (isinstance(val, str) and val.strip() == ""):
                    raise ValidationError(
                        f"Field '{field}' in application {app.get('app_id', idx)} cannot be empty or null."
                    )

        # Validate duplicates in app_id
        app_id = app["app_id"]
        if app_id in seen_app_ids:
            raise ValidationError(f"Duplicate application ID detected: '{app_id}'")
        seen_app_ids.add(app_id)

    logger.info(f"Successfully loaded and validated {len(data)} applications.")
    return data


def load_sbom_dependencies(file_path: str) -> pd.DataFrame:
    """
    Loads sbom_dependencies.csv and validates its structure and contents.

    Args:
        file_path: Path to sbom_dependencies.csv.

    Returns:
        A pandas DataFrame containing dependency records.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValidationError: If validation fails (missing columns, missing values, duplicates).
        DataLoaderError: If CSV parsing fails.
    """
    logger.info(f"Loading SBOM dependencies from: {file_path}")
    validate_file_path(file_path)

    try:
        df = pd.read_csv(file_path, keep_default_na=False)
    except Exception as e:
        raise DataLoaderError(f"Failed to read CSV file {file_path}: {e}") from e

    required_columns = [
        "app_id", "dependency_name", "ecosystem", "version",
        "latest_version", "dependency_type", "license", "supplier", "last_updated"
    ]

    # Validate required columns presence
    missing_cols = set(required_columns) - set(df.columns)
    if missing_cols:
        raise ValidationError(f"SBOM dependencies CSV is missing required columns: {missing_cols}")

    # Validate missing values in required fields
    for col in required_columns:
        if df[col].isna().any():
            null_count = df[col].isna().sum()
            raise ValidationError(
                f"Column '{col}' in SBOM dependencies contains {null_count} null or missing value(s)."
            )
        # Check for empty strings/spaces
        if df[col].dtype == object:
            empty_mask = df[col].astype(str).str.strip() == ""
            if empty_mask.any():
                raise ValidationError(
                    f"Column '{col}' in SBOM dependencies contains empty string values."
                )

    # Validate duplicates for unique composite key: app_id + dependency_name + version
    unique_key = ["app_id", "dependency_name", "version"]
    duplicate_mask = df.duplicated(subset=unique_key, keep=False)
    if duplicate_mask.any():
        duplicate_records = df[duplicate_mask][unique_key].drop_duplicates()
        raise ValidationError(
            f"Duplicate dependency records detected for the keys:\n{duplicate_records.to_dict(orient='records')}"
        )

    logger.info(f"Successfully loaded and validated {len(df)} dependency records.")
    return df


def load_vulnerability_db(file_path: str) -> List[Dict[str, Any]]:
    """
    Loads vulnerability_db.json and validates its structure and contents.

    Args:
        file_path: Path to vulnerability_db.json.

    Returns:
        A list of vulnerability dictionaries.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValidationError: If validation fails (missing fields, empty fields, duplicates).
        DataLoaderError: If JSON decoding fails.
    """
    logger.info(f"Loading vulnerability database from: {file_path}")
    validate_file_path(file_path)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise DataLoaderError(f"Failed to parse JSON file {file_path}: {e}") from e

    if not isinstance(data, list):
        raise ValidationError("vulnerability_db.json must contain a JSON array/list at the root.")

    required_fields = {
        "cve_id", "dependency_name", "affected_versions", "fixed_version",
        "cvss_score", "severity", "exploit_available", "patch_available", "published_date"
    }

    seen_cve_ids = set()

    for idx, vuln in enumerate(data):
        if not isinstance(vuln, dict):
            raise ValidationError(f"Vulnerability record at index {idx} is not a JSON object.")

        # Check required fields presence
        missing_fields = required_fields - vuln.keys()
        if missing_fields:
            raise ValidationError(
                f"Vulnerability record at index {idx} is missing required fields: {missing_fields}"
            )

        # Validate types and non-emptiness
        for field in required_fields:
            val = vuln[field]
            if field == "affected_versions":
                if not isinstance(val, list):
                    raise ValidationError(
                        f"Field 'affected_versions' in vulnerability {vuln.get('cve_id', idx)} must be a list."
                    )
            elif field in ("exploit_available", "patch_available"):
                if not isinstance(val, bool):
                    raise ValidationError(
                        f"Field '{field}' in vulnerability {vuln.get('cve_id', idx)} must be a boolean."
                    )
            elif field == "cvss_score":
                if not isinstance(val, (int, float)):
                    raise ValidationError(
                        f"Field 'cvss_score' in vulnerability {vuln.get('cve_id', idx)} must be a number."
                    )
                if not (0.0 <= float(val) <= 10.0):
                    raise ValidationError(
                        f"CVSS score in vulnerability {vuln.get('cve_id', idx)} must be between 0.0 and 10.0."
                    )
            else:
                if val is None or (isinstance(val, str) and val.strip() == ""):
                    raise ValidationError(
                        f"Field '{field}' in vulnerability {vuln.get('cve_id', idx)} cannot be empty or null."
                    )

        # Validate duplicates in cve_id + dependency_name
        cve_id = vuln["cve_id"]
        dep_name = vuln["dependency_name"]
        combo_key = (cve_id, dep_name)
        if combo_key in seen_cve_ids:
            raise ValidationError(f"Duplicate vulnerability record detected for CVE ID '{cve_id}' on dependency '{dep_name}'")
        seen_cve_ids.add(combo_key)

    logger.info(f"Successfully loaded and validated {len(data)} vulnerability records.")
    return data


def load_license_rules(file_path: str) -> List[Dict[str, Any]]:
    """
    Loads license_rules.json and validates its structure and contents.

    Args:
        file_path: Path to license_rules.json.

    Returns:
        A list of license rule dictionaries.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValidationError: If validation fails (missing fields, empty fields, duplicates).
        DataLoaderError: If JSON decoding fails.
    """
    logger.info(f"Loading license rules from: {file_path}")
    validate_file_path(file_path)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise DataLoaderError(f"Failed to parse JSON file {file_path}: {e}") from e

    if not isinstance(data, list):
        raise ValidationError("license_rules.json must contain a JSON array/list at the root.")

    required_fields = {
        "license_name", "risk_level", "commercial_use_allowed", "copyleft",
        "patent_grant", "compatible_with", "incompatible_with"
    }

    seen_license_names = set()

    for idx, rule in enumerate(data):
        if not isinstance(rule, dict):
            raise ValidationError(f"License rule record at index {idx} is not a JSON object.")

        # Check required fields presence
        missing_fields = required_fields - rule.keys()
        if missing_fields:
            raise ValidationError(
                f"License rule record at index {idx} is missing required fields: {missing_fields}"
            )

        # Validate types and non-emptiness
        for field in required_fields:
            val = rule[field]
            if field in ("compatible_with", "incompatible_with"):
                if not isinstance(val, list):
                    raise ValidationError(
                        f"Field '{field}' in license {rule.get('license_name', idx)} must be a list."
                    )
            elif field in ("commercial_use_allowed", "copyleft", "patent_grant"):
                if not isinstance(val, bool):
                    raise ValidationError(
                        f"Field '{field}' in license {rule.get('license_name', idx)} must be a boolean."
                    )
            else:
                if val is None or (isinstance(val, str) and val.strip() == ""):
                    raise ValidationError(
                        f"Field '{field}' in license {rule.get('license_name', idx)} cannot be empty or null."
                    )

        # Validate duplicates in license_name
        license_name = rule["license_name"]
        if license_name in seen_license_names:
            raise ValidationError(f"Duplicate license name detected: '{license_name}'")
        seen_license_names.add(license_name)

    logger.info(f"Successfully loaded and validated {len(data)} license rules.")
    return data


def load_dependency_labels(file_path: str) -> pd.DataFrame:
    """
    Loads dependency_labels.csv and validates its structure and contents.

    Args:
        file_path: Path to dependency_labels.csv.

    Returns:
        A pandas DataFrame containing risk status labels.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValidationError: If validation fails (missing columns, missing values, duplicates).
        DataLoaderError: If CSV parsing fails.
    """
    logger.info(f"Loading dependency labels from: {file_path}")
    validate_file_path(file_path)

    try:
        df = pd.read_csv(file_path, keep_default_na=False)
    except Exception as e:
        raise DataLoaderError(f"Failed to read CSV file {file_path}: {e}") from e

    required_columns = [
        "app_id", "dependency_name", "version", "risk_status", "risk_type", "severity", "explanation"
    ]

    # Validate required columns presence
    missing_cols = set(required_columns) - set(df.columns)
    if missing_cols:
        raise ValidationError(f"Dependency labels CSV is missing required columns: {missing_cols}")

    # Validate missing values in required fields
    for col in required_columns:
        if df[col].isna().any():
            null_count = df[col].isna().sum()
            raise ValidationError(
                f"Column '{col}' in dependency labels contains {null_count} null or missing value(s)."
            )
        # Check for empty strings/spaces
        if df[col].dtype == object:
            empty_mask = df[col].astype(str).str.strip() == ""
            if empty_mask.any():
                raise ValidationError(
                    f"Column '{col}' in dependency labels contains empty string values."
                )

    # Validate duplicate records for composite key: app_id + dependency_name + version
    unique_key = ["app_id", "dependency_name", "version"]
    duplicate_mask = df.duplicated(subset=unique_key, keep=False)
    if duplicate_mask.any():
        duplicate_records = df[duplicate_mask][unique_key].drop_duplicates()
        raise ValidationError(
            f"Duplicate label records detected for the keys:\n{duplicate_records.to_dict(orient='records')}"
        )

    # Validate valid categories of risk_status, risk_type, and severity
    valid_risk_status = {"Safe", "Risky"}
    valid_risk_types = {"Vulnerability", "License", "Unmaintained", "Transitive", "None"}
    valid_severities = {"None", "Low", "Medium", "High", "Critical"}

    invalid_status = df[~df["risk_status"].isin(valid_risk_status)]
    if not invalid_status.empty:
        raise ValidationError(
            f"Invalid values in 'risk_status': {invalid_status['risk_status'].unique()}. Must be one of {valid_risk_status}."
        )

    invalid_types = df[~df["risk_type"].isin(valid_risk_types)]
    if not invalid_types.empty:
        raise ValidationError(
            f"Invalid values in 'risk_type': {invalid_types['risk_type'].unique()}. Must be one of {valid_risk_types}."
        )

    invalid_severities = df[~df["severity"].isin(valid_severities)]
    if not invalid_severities.empty:
        raise ValidationError(
            f"Invalid values in 'severity': {invalid_severities['severity'].unique()}. Must be one of {valid_severities}."
        )

    logger.info(f"Successfully loaded and validated {len(df)} dependency label records.")
    return df


def load_all_data(data_directory: str) -> Tuple[
    List[Dict[str, Any]],  # applications
    pd.DataFrame,          # sbom_dependencies
    List[Dict[str, Any]],  # vulnerability_db
    List[Dict[str, Any]],  # license_rules
    pd.DataFrame           # dependency_labels
]:
    """
    Loads and validates all five SBOM Analyzer dataset files from the specified directory.

    Expected file names in the directory:
    - applications.json
    - sbom_dependencies.csv
    - vulnerability_db.json
    - license_rules.json
    - dependency_labels.csv

    Args:
        data_directory: Path to the directory where the dataset files are located.

    Returns:
        A tuple of (applications, sbom_dependencies, vulnerability_db, license_rules, dependency_labels).

    Raises:
        FileNotFoundError: If any of the required files are missing.
        ValidationError: If any file content fails validation checks.
        DataLoaderError: If file reading or parsing fails.
    """
    logger.info(f"Initiating bulk load of SBOM dataset from directory: {data_directory}")

    app_path = os.path.join(data_directory, "applications.json")
    deps_path = os.path.join(data_directory, "sbom_dependencies.csv")
    vuln_path = os.path.join(data_directory, "vulnerability_db.json")
    rules_path = os.path.join(data_directory, "license_rules.json")
    labels_path = os.path.join(data_directory, "dependency_labels.csv")

    # Load and validate files sequentially
    applications = load_applications(app_path)
    sbom_dependencies = load_sbom_dependencies(deps_path)
    vulnerability_db = load_vulnerability_db(vuln_path)
    license_rules = load_license_rules(rules_path)
    dependency_labels = load_dependency_labels(labels_path)

    # Perform cross-file consistency validation
    logger.info("Performing cross-dataset consistency validation...")

    # 1. Verify every app_id in sbom_dependencies and dependency_labels exists in applications
    valid_app_ids = {app["app_id"] for app in applications}

    dep_app_ids = set(sbom_dependencies["app_id"].unique())
    missing_apps_deps = dep_app_ids - valid_app_ids
    if missing_apps_deps:
        raise ValidationError(
            f"Ecosystem dependencies reference app_ids not present in applications.json: {missing_apps_deps}"
        )

    label_app_ids = set(dependency_labels["app_id"].unique())
    missing_apps_labels = label_app_ids - valid_app_ids
    if missing_apps_labels:
        raise ValidationError(
            f"Dependency labels reference app_ids not present in applications.json: {missing_apps_labels}"
        )

    # 2. Verify dependencies and labels map 1-to-1 on (app_id, dependency_name, version)
    deps_keys = set(zip(sbom_dependencies["app_id"], sbom_dependencies["dependency_name"], sbom_dependencies["version"]))
    labels_keys = set(zip(dependency_labels["app_id"], dependency_labels["dependency_name"], dependency_labels["version"]))

    unmatched_in_labels = deps_keys - labels_keys
    if unmatched_in_labels:
        raise ValidationError(
            f"Dependencies present in sbom_dependencies.csv but missing from dependency_labels.csv: {list(unmatched_in_labels)[:5]}..."
        )

    unmatched_in_deps = labels_keys - deps_keys
    if unmatched_in_deps:
        raise ValidationError(
            f"Dependencies present in dependency_labels.csv but missing from sbom_dependencies.csv: {list(unmatched_in_deps)[:5]}..."
        )

    logger.info("Cross-dataset consistency checks passed successfully.")
    logger.info("All SBOM Analyzer data files successfully loaded and validated.")

    return (
        applications,
        sbom_dependencies,
        vulnerability_db,
        license_rules,
        dependency_labels
    )
