VRV-Security-Python-Intern-Assignment
This repository contains the solution for VRV Security's Python Intern Assignment. It processes log files to extract and analyze key data, demonstrating skills in file handling, string manipulation, and data analysis, crucial for cybersecurity programming tasks.
Table of Contents
Objective
Features
Installation
File Structure
Requirements
Setup
Results
Usage
Output Details
Evaluation Criteria
Author
Objective
The primary goal of this script is to:

Process log files to extract valuable insights.
Automate tasks like identifying suspicious activities and determining user behavior trends.
Produce a clean, structured output in the terminal and a CSV file for reporting purposes.
Features
The script implements the following functionalities:

Count Requests per IP Address:

Parses the log file to identify unique IP addresses and their request counts.
Sorts the results in descending order of request counts for quick interpretation.
Identify the Most Frequently Accessed Endpoint:

Extracts all accessed endpoints from the log file.
Highlights the most frequently accessed endpoint along with its access count.
Detect Suspicious Activity:

Identifies potential brute force login attempts:
Flags IP addresses with failed login attempts exceeding a configurable threshold (default: 10).
Detects log entries indicating failed login attempts using HTTP status codes (401) or failure messages.
Output Results:

Displays findings in an organized format in the terminal.
Saves results to a CSV file named log_analysis_results.csv with the following structure:
Requests per IP: IP Address, Request Count
Most Accessed Endpoint: Endpoint, Access Count
Suspicious Activity: IP Address, Failed Login Count
Installation
Clone this repository:
bash
Copy code
git clone VRV Security Python Intern Assignment
This repository contains the solution for VRV Security's Python Intern Assignment. The project processes web server log files to extract and analyze key data, demonstrating expertise in log file parsing, string manipulation, and data analysis—critical skills for cybersecurity tasks.

Table of Contents
Objective
Features
Installation
File Structure
Requirements
Setup
Results
Usage
Output Details
Evaluation Criteria
Author
Objective
The primary goal of this script is to:

Process log files to extract valuable insights.
Automate tasks like identifying suspicious activities and determining user behavior trends.
Produce a clean, structured output in the terminal and a CSV file for reporting purposes.
Features
The script implements the following functionalities:

Count Requests per IP Address:

Parses the log file to identify unique IP addresses and their request counts.
Sorts the results in descending order of request counts for quick interpretation.
Identify the Most Frequently Accessed Endpoint:

Extracts all accessed endpoints from the log file.
Highlights the most frequently accessed endpoint along with its access count.
Detect Suspicious Activity:

Identifies potential brute force login attempts:
Flags IP addresses with failed login attempts exceeding a configurable threshold (default: 10).
Detects log entries indicating failed login attempts using HTTP status codes (401) or failure messages.
Output Results:

Displays findings in an organized format in the terminal.
Saves results to a CSV file named log_analysis_results.csv with the following structure:
Requests per IP: IP Address, Request Count
Most Accessed Endpoint: Endpoint, Access Count
Suspicious Activity: IP Address, Failed Login Count
Installation
Clone this repository:

bash
Copy code
git clone https://github.com/preethamthilak2209/VRV-assignment-_python-Intern_2024.git
Navigate to the project directory:

bash
Copy code
cd VRV-assignment-_python-Intern_2024
Install the required dependencies:

bash
Copy code
pip install -r requirements.txt
File Structure
bash
Copy code
.
├── sample.log                    # Example log file for testing
├── log_analysis_results.csv      # Output CSV file with analysis results
├── README.md                     # Project documentation
└── log_analysis.py               # Python script for log analysis
Requirements
Python 3.8+
Libraries:
pandas
numpy
Setup
Clone the repository:

bash
Copy code
git clone https://github.com/preethamthilak2209/VRV-assignment-_python-Intern_2024.git
cd VRV-assignment-_python-Intern_2024
Install the required libraries:

bash
Copy code
pip install pandas numpy
Place your log file in the project directory with the name sample.log.

Results
Terminal Output Example:
yaml
Copy code
IP Address Analysis:
192.168.1.1 - 120 requests
192.168.1.2 - 80 requests
...

Most Accessed Endpoint:
/api/login - 150 requests

Suspicious IPs:
192.168.1.3 - 15 failed login attempts
CSV Output:
The CSV file log_analysis_results.csv will include:

IP Address	Request Count	Most Accessed Endpoint	Suspicious Activity
192.168.1.1	120	/api/data	No
192.168.1.3	50	/api/login	Yes (15 attempts)
Usage
Place the log file in the project directory.

Run the script by providing the log file as an argument:

bash
Copy code
python log_analysis.py <logfile>
View the results in the terminal and check the log_analysis_results.csv for a detailed report.

Output Details
The script generates the following:

Terminal Output:

Count of requests per IP, sorted in descending order.
The most frequently accessed endpoint and its count.
Suspicious activities with flagged IPs and failed login counts.
CSV File:

log_analysis_results.csv with:
Requests per IP: IP Address, Request Count
Most Accessed Endpoint: Endpoint, Access Count
Suspicious Activity: IP Address, Failed Login Count
Evaluation Criteria
Functionality:

Properly implements all required analysis features.
Handles the provided log file accurately and efficiently.
Code Quality:

Follows Python best practices with clean, modular, and well-commented code.
Uses meaningful variable names and clear function definitions.
Performance:

Processes large log files without significant delays.
Output:

Displays a structured and accurate terminal output.
Creates a correctly formatted CSV file matching specifications.
Author
This project was developed by P Preetham Thilak. 
Navigate to the project directory:
bash
Copy code
cd Log-Analysis-Script  
Install the required dependencies:
bash
Copy code
pip install -r requirements.txt  
File Structure
bash
Copy code
.
├── VRV_Security_Assignment.ipynb  # Jupyter notebook with the complete solution
├── sample.log                    # Example log file for testing
├── log_analysis_results.csv      # Output CSV file with analysis results
└── README.md                     # Project documentation
Requirements
Python 3.8+
Libraries:
pandas
numpy
Setup
Clone the repository:

bash
Copy code
git clone https://github.com/<your-username>/vrv-security-assignment.git  
cd vrv-security-assignment  
Install the required libraries:

bash
Copy code
pip install pandas numpy  
Place your log file in the project directory with the name sample.log.

Results
Terminal Output Example:
IP Address Analysis:
192.168.1.1 - 120 requests
192.168.1.2 - 80 requests
...

Most Accessed Endpoint:
/api/login - 150 requests

Suspicious IPs:
192.168.1.3 - 15 failed login attempts

CSV Output:
The CSV file log_analysis_results.csv will include:

IP Address	Request Count	Most Accessed Endpoint	Suspicious Activity
192.168.1.1	120	/api/data	No
192.168.1.3	50	/api/login	Yes (15 attempts)
Usage
Place the log file in the project directory.

Run the script by providing the log file as an argument:

bash
Copy code
python log_analysis.py <logfile>  
View the results in the terminal and check the log_analysis_results.csv for a detailed report.

Output Details
The script generates the following:

Terminal Output:

Count of requests per IP, sorted in descending order.
The most frequently accessed endpoint and its count.
Suspicious activities with flagged IPs and failed login counts.
CSV File:

log_analysis_results.csv with:
Requests per IP: IP Address, Request Count
Most Accessed Endpoint: Endpoint, Access Count
Suspicious Activity: IP Address, Failed Login Count
Evaluation Criteria
Functionality:
Properly implements all required analysis features.
Handles the provided log file accurately and efficiently.
Code Quality:
Follows Python best practices with clean, modular, and well-commented code.
Uses meaningful variable names and clear function definitions.
Performance:
Processes large log files without significant delays.
Output:
Displays a structured and accurate terminal output.
Creates a correctly formatted CSV file matching specifications.


Author
This project was developed by P Preetham Thilak.

