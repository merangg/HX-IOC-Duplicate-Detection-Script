# **IOC Rule Deduplication Script**

## **Overview**
This Python script helps security analysts detect and remove duplicate entries in `.rules` files. It checks for duplicates both within the newly uploaded `.rules` files and against a large existing repository. The script is intended to be run once a week for rule cleanup and repository management.

## **How It Works**
1. **Deduplicates**: The script scans directories containing `.rules` files for duplicates.
2. **Repository Check**: Cross-checks the new rules with the existing repository to avoid reintroducing duplicates.
3. **Audit Log**: Logs the results of each script run, including user and system information.
4. **Outputs**:
   - `extracted_values.json`: Extracted values from the `.rules` files.
   - `duplicates_<date>.txt`: Report showing duplicates found.
   - `repository.json`: Updated repository of rules.
   - `audit_log.txt`: Detailed log of each run.

## **Installation**
1. **Clone the repo**:
   ```bash
   git clone https://github.com/yourusername/ioc-rule-deduplication-script.git
2. **Install dependencies**
    ```bash
    pip install tqdm chardet

## **Usage**
1. Prepare your .rules files.
2. Run the script
3. Enter the directories where your .rules files are stored.

## **Contributing**
Feel free to fork the repo and submit pull requests for improvements!
