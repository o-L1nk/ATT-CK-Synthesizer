# ATT&CK Synthesizer

## Introduction

The ATT&CK Synthesizer is a tool designed to streamline red teaming activities. It helps users scan for vulnerabilities on a specified target and select one or more sub-techniques from the MITRE ATT&CK Framework. The tool then generates custom exploits to exploit identified vulnerabilities on the target system, making it an essential utility for cybersecurity professionals.

## Installation

To get started with the ATT&CK Synthesizer, you'll need to install several tools and dependencies. Follow the steps below to set up your environment:

## Setup

Run the command below to set up:
sudo python3 setup.py


Do the belows in case setup.py don't work
### 1. Python Installation

If you do not have Python installed on your system, follow these steps to install it:

1. **Ubuntu/Debian-based systems:**

   ```bash
   sudo apt update
   sudo apt install python3

2. **Red Hat/CentOS-based systems:**

   ```bash
   sudo yum install python3

3. **Windows:**
Windows:

Download the latest version of Python from the official Python website.
Run the installer and ensure that you check the option to "Add Python to PATH" during installation.

### 2. Nmap

Nmap is a network scanning tool that ATT&CK Synthesizer relies on for detecting vulnerabilities. Ensure Nmap is installed on your system:

1. Check if Nmap is already installed:
    ```bash
    nmap --version
    ```
2. If Nmap is not installed, you can install it using:
    ```bash
    sudo apt install nmap
    ```

### 3. Selenium and Geckodriver

The ATT&CK Synthesizer uses Selenium for browser automation, specifically to interact with web applications. To set this up:

1. Install Selenium:
    ```bash
    sudo apt-get install python3-selenium
    pip install selenium
    ```
2. Install Geckodriver (for Firefox browser):
    - Download the latest version of Geckodriver from the [official GitHub releases page](https://github.com/mozilla/geckodriver/releases).
    - Extract the downloaded file and move it to a directory in your system's PATH:
        ```bash
        sudo mv geckodriver /usr/local/bin/
        sudo chmod +x /usr/local/bin/geckodriver
        ```
    - This setup is necessary for Selenium to control the Firefox browser during automated tasks.

### 4. Vulnerability Scanner

To enhance vulnerability scanning capabilities, the ATT&CK Synthesizer integrates with Vulscan, an additional tool that extends Nmap's functionality:

1. Clone the Vulscan repository from GitHub:
    ```bash
    sudo git clone https://github.com/scipag/vulscan
    ```
2. Move the `vulscan` directory to Nmap's scripts folder:
    ```bash
    sudo mv vulscan /usr/share/nmap/scripts/vulscan
    ```
    - This step ensures that Nmap can use the Vulscan scripts for more detailed vulnerability analysis.

### 5. Python Dependencies

The ATT&CK Synthesizer relies on several Python libraries for various functionalities, including web requests, and system monitoring. Install these dependencies using the following command:

```bash
pip install requests selenium beautifulsoup4 psutil
```

requests: For making HTTP requests to web services.
selenium: For browser automation.
beautifulsoup4: For parsing HTML and XML documents.
psutil: For system and process utilities.


## Usage

Note: Ensure that the files and Directories below are all in the same directory: 

Files:
- synthesizer_art.py  
- vulscanner.py
- atomic_commands.py
- getsuid.py

Directories:
- atomics ()
- _gtfobins ()


You have to run the following command to start the program:
    python3 synthesizer_art.py

In the program:
	Once the program is running:

	- Follow the interactive menu to select the appropriate MITRE ATT&CK sub-techniques that align with your red teaming objectives.
	- The program will guide you through generating and executing custom exploits based on the vulnerabilities detected on the target system.

Using vulnerability scanner:
	There are 3 available scans in the system:

	- Vulscanner - Scan target's open ports and CVE vulnerabilties (Requires IP Address of target)
	- WinEnum - Scan vulnerabilties and information in a Windows System (Requires IP Address of target)
	- LinPeas - Scan vulnerabilties and information in a Linux System including Privilege Escalation Exploits (Requires IP Address of target and Take note ssh access is to be required on the target)

Using exploit generator:
	We only cover Windows and Linux techniques for now, and we cover Persistence, Privilege Escalation and Defense Evasion techniques only, take note as this is a major project, not all techniques is covered:

	To ensure a better success generation, please do not select too many techniques at once. (more than 5)

Troubleshooting:
If you encounter any issues during installation or while running the program, consider the following:

- Nmap not recognized: Ensure that Nmap is correctly installed and added to your system's PATH.
- Selenium/Geckodriver issues: Double-check that Geckodriver is correctly installed and that Selenium is compatible with your version of Firefox.
- Vulscan scripts not found: Verify that the vulscan folder is correctly placed in the /usr/share/nmap/scripts/ directory.



