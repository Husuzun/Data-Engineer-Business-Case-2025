# CVE Data Processing Pipeline

This project implements a data engineering pipeline that processes CVE (Common Vulnerabilities and Exposures) data, extracts operating system information, matches it with a reference list using LLM-based normalization, and stores the results in a PostgreSQL database.

## Pipeline Architecture

```
┌───────────┐       ┌───────────┐      ┌───────────────┐      ┌───────────────┐
│ Download  │       │ Extract   │      │ Process CVE   │      │ LLM-based     │
│ CVE Data  │──────>│ 2024 CVEs │─────>│ JSON Files    │─────>│ OS Matching   │
└───────────┘       └───────────┘      └───────────────┘      └───────────────┘
                                                                      │
                                                                      ▼
┌───────────────┐      ┌───────────────┐      ┌───────────────┐      │
│ Store         │      │ Insert        │      │ Set up        │      │
│ Results       │<─────│ CVE Data      │<─────│ Database      │<─────┘
└───────────────┘      └───────────────┘      └───────────────┘
```

## Requirements

- Python 3.8+
- PostgreSQL database
- Ollama (local LLM) running on port 11434

## Setup Instructions

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Database

Ensure you have PostgreSQL installed and running. Create a database called `cvedb`:

```bash
createdb cvedb
```

### 3. Configuration

All configuration settings are centralized in `config.py`. Update this file to modify:

- Database connection parameters
- Ollama API settings
- OS reference list
- File paths and URLs

```python
# Example: Updating database password
PG_PASSWORD = "your_secure_password"

# Example: Changing Ollama model
OLLAMA_MODEL = "llama2" 
```

### 4. Run the Pipeline

```bash
python Data_Engineer_Business_Case.py
```

Alternatively, to reset the database and run the complete pipeline:

```bash
python reset_and_run.py
```

## Database Schema Design

The database uses a normalized schema design to efficiently store CVE data and OS matching information:

### Tables

1. **cve_records**: Stores the main CVE information
   - Primary key: `id`
   - Unique constraint: `cve_id`
   - Contains: description, vulnerability status, dates, CVSS scores, etc.

2. **os_reference**: Reference table for the operating systems list
   - Primary key: `id`
   - Unique constraint: `os_name`
   - Contains: OS names from the reference list

3. **matched_os**: Stores matched OS information (normalized)
   - Primary key: `id`
   - Foreign keys: `cve_id` references `cve_records`, `os_id` references `os_reference`
   - Contains: original OS text and matched reference OS

4. **unmatched_os**: Stores unmatched OS information
   - Primary key: `id`
   - Foreign key: `cve_id` references `cve_records`
   - Contains: original OS text that couldn't be matched

### Schema Rationale

- **Normalization**: The schema follows database normalization principles to reduce redundancy
- **Referential Integrity**: Foreign key constraints ensure data consistency
- **Separation of Concerns**: Matched and unmatched OS information are stored in separate tables
- **Traceability**: Original OS text is preserved alongside matched references

## Data Validation Approach

The pipeline includes several validation steps:

1. **Input Validation**: Checks if CVE data structure is valid before processing
2. **OS Matching Validation**: Uses LLM confidence scores to validate matching quality
3. **Database Constraints**: Enforces referential integrity at the database level
4. **Error Handling**: Comprehensive error handling with logging for traceability

## Utility Scripts

The project includes several utility scripts:

1. **check_os_records.py**: Generate a summary report of OS matching results
2. **reset_and_run.py**: Reset the database and run the pipeline from scratch

## DBT Integration for Validation

A DBT model provides advanced validation capabilities:

1. **os_match_validation**: Identifies and prioritizes CVEs for manual review
   - Categorizes match quality
   - Detects potential false matches
   - Assigns validation priority levels

To run the DBT model:

```bash
cd dbt_validation
dbt run
```
