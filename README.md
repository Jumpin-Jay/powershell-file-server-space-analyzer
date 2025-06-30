# PowerShell File Server Space Analyzer: Optimize Your Storage Efficiently

![GitHub release](https://img.shields.io/github/release/Jumpin-Jay/powershell-file-server-space-analyzer.svg) ![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Overview

The **PowerShell File Server Space Analyzer** is a robust script designed for analyzing disk space on file servers. It identifies duplicate files, large files, and old files, providing an interactive HTML dashboard for easy visualization. This tool helps in optimizing storage, ensuring that your file server runs efficiently.

## Features

- **Duplicate File Detection**: Quickly find and manage duplicate files to free up space.
- **Large and Old File Identification**: Spot large and outdated files that may be taking up unnecessary space.
- **Interactive HTML Dashboard**: Visualize your storage usage through an easy-to-navigate dashboard.
- **NTFS Support**: Fully compatible with NTFS file systems.
- **Read-Only Operation**: Safely analyze without modifying any files.
- **Sanitization Options**: Ensure sensitive data is handled appropriately.

## Topics

This project covers various topics that enhance your file server management:

- Cleanup
- Dashboard
- Deduplication
- Duplicate Files
- File Server
- HTML Report
- NTFS
- PowerShell Script
- Read-Only
- Sanitization
- Space Analysis
- Storage Optimization
- Windows Server

## Getting Started

To get started with the **PowerShell File Server Space Analyzer**, you need to download the latest release. You can find it [here](https://github.com/Jumpin-Jay/powershell-file-server-space-analyzer/releases). After downloading, follow the instructions below to execute the script.

### Prerequisites

Ensure you have the following before running the script:

- Windows Server with PowerShell installed.
- Administrative privileges to access file directories.
- Basic understanding of PowerShell commands.

### Installation

1. **Download the Script**: Go to the [Releases section](https://github.com/Jumpin-Jay/powershell-file-server-space-analyzer/releases) and download the latest version of the script.
2. **Extract the Files**: Unzip the downloaded file to a folder of your choice.
3. **Open PowerShell**: Right-click on the Start menu and select "Windows PowerShell (Admin)".
4. **Navigate to the Script Location**: Use the `cd` command to change the directory to where you extracted the files.

   ```powershell
   cd "C:\path\to\your\script\folder"
   ```

5. **Run the Script**: Execute the script with the following command:

   ```powershell
   .\SpaceAnalyzer.ps1
   ```

### Usage

Once the script runs, it will analyze your file server and generate a detailed HTML report. The report will display:

- Total disk space used
- Number of duplicate files
- List of large files
- List of old files
- Interactive charts and graphs for better understanding

## Dashboard Overview

The HTML dashboard provides a user-friendly interface to visualize the data collected during the analysis. Key components include:

- **Storage Usage Pie Chart**: Shows the proportion of space used by different file types.
- **Duplicate Files Table**: Lists all duplicates found, allowing for easy management.
- **Large Files List**: Displays files that exceed a specified size threshold.
- **Old Files List**: Identifies files that have not been modified in a long time.

### Example Dashboard

![Dashboard Example](https://example.com/dashboard.png)

*Note: Replace with an actual image link relevant to the project.*

## Customization

You can customize the script to suit your needs. Here are a few parameters you might want to adjust:

- **File Size Threshold**: Change the size limit for large files.
- **Date Threshold**: Modify the date to filter old files.
- **Output Directory**: Specify where to save the HTML report.

To customize, open the script in a text editor and look for the configuration section.

## Troubleshooting

If you encounter issues while running the script, consider the following:

- **Permission Errors**: Ensure you have administrative rights.
- **Path Errors**: Double-check the file paths you provide in the script.
- **PowerShell Execution Policy**: If the script does not run, you may need to change your execution policy. Run this command in PowerShell:

   ```powershell
   Set-ExecutionPolicy RemoteSigned
   ```

## Contribution

Contributions are welcome! If you have suggestions or improvements, please fork the repository and submit a pull request. Make sure to follow the code style and include tests for any new features.

### How to Contribute

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your branch to your fork.
5. Open a pull request against the main repository.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or issues, please reach out to the repository owner or create an issue in the GitHub repository.

## Download the Latest Release

To download the latest version of the script, visit the [Releases section](https://github.com/Jumpin-Jay/powershell-file-server-space-analyzer/releases). After downloading, follow the installation instructions provided above to start optimizing your file server space.

## Conclusion

The **PowerShell File Server Space Analyzer** is a powerful tool for managing disk space on your file servers. By identifying duplicates, large files, and outdated files, it helps you maintain an organized and efficient storage system. Use the interactive dashboard to visualize your storage usage and make informed decisions about your file management.

![PowerShell Logo](https://example.com/powershell_logo.png)

*Note: Replace with an actual image link relevant to the project.*