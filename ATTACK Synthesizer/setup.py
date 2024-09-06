import os
import subprocess
import shutil
import sys

def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def run_command(command):
    subprocess.run(command, shell=True, check=True)

def main():
    try:
        print("Starting the setup process...")

        # 1. Install Python dependencies
        print("Installing Python dependencies...")
        packages = [
            "mysql-connector-python",
            "requests",
            "selenium",
            "beautifulsoup4",
            "psutil"
        ]
        for package in packages:
            install_package(package)

        # 2. Install Nmap (Linux)
        if os.name == 'posix':
            print("Installing Nmap...")
            run_command("sudo apt install nmap -y")
            

        # 3. Install Selenium and Geckodriver (Linux)
        if os.name == 'posix':
            print("Installing Selenium and Geckodriver...")
            run_command("sudo apt-get install python3-selenium -y")

            # Download and install Geckodriver
            print("Installing Geckodriver...")
            run_command("wget https://github.com/mozilla/geckodriver/releases/download/v0.35.0/geckodriver-v0.35.0-linux64.tar.gz")
            run_command("tar -xvzf geckodriver-v0.35.0-linux64.tar.gz")
            run_command("sudo mv geckodriver /usr/local/bin/")
            run_command("sudo chmod +x /usr/local/bin/geckodriver")
            run_command("rm geckodriver-v0.35.0-linux64.tar.gz")

        # 4. Clone and setup Vulscan
        if os.name == 'posix':
            print("Cloning and setting up Vulscan...")
            if not os.path.exists("/usr/share/nmap/scripts/vulscan"):
                run_command("sudo git clone https://github.com/scipag/vulscan")
                run_command("sudo mv vulscan /usr/share/nmap/scripts/vulscan")

        # 5. Clone additional repositories
        if os.name == 'posix':
            print("Cloning Atomic Red Team repository...")
            if not os.path.exists("atomic-red-team"):
                run_command("sudo git clone https://github.com/redcanaryco/atomic-red-team.git")

            print("Cloning GTFOBins repository...")
            if not os.path.exists("GTFOBins.github.io"):
                run_command("sudo git clone https://github.com/GTFOBins/GTFOBins.github.io.git")

        # 6. Copy the T1564.002.md file to the desired location
        source_path = "customtestcase/T1564.002.md"
        destination_path = "atomic-red-team/atomics/T1564.002/T1564.002.md"
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)
        shutil.copy2(source_path, destination_path)
        print("T1564.002.md file copied successfully.")

        print("Setup completed successfully!")

    except Exception as e:
        print(f"Setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
