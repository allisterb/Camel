# Camel

## About
The Camel project is a code-mode MCP server that allows LLMs to safely generate and execute JavaScript code that calls command-line forensic tools, performs analysis, and employs traditional machine learning algorithms and probabilistic reasoning using [SIFT workstation](https://www.sans.org/tools/sift-workstation), for autonomous DFIR investigations. 

## Example case data
Full reports and audit logs for cases investigated using Claude + Camel can be downloaded from: https://drive.google.com/drive/folders/1whw7GwrZUxADTsy1f-LCV2jN-Q-fpVNp?usp=sharing

## Getting started
1. Download the latest Windows or *nix release to your computer.

2. Edit the appsettings.json in your Camel folder and set your SIFT environment preference: Local/Ssh. If using Ssh enter the login details for the SIFT workstation. You can also set MaxConcurrentExecutions to limit how many concurrent executions are allowed on SIFT.

3. From the `Camel` folder run `[./]camel create-case <case_dir> <case_id>`
where <case_dir> is the path to your cases directory and <case_id> is your case id. Camel will create a case directory at the specified path with the CLAUDE.md prompt file and other supporting files and directories.

4. Edit <case_dir>/<case_id>/CLAUDE.md and fill in the Case description and Evidence sections with your case details and the filepaths to the evidence files on the SIFT workstation.

5. Start a new Claude session in <case_dir>/<case_id>.

6. Tell the agent to begin the investigation. The agent will first check if the required evidence files are present. ifyou provide hashes it will ask  you if you want to verify the evidence files first. After it confirms the evidence it will proceed autonomously.

7. As the investigation proceeds audit log data is writtten to the logs directory in CLEF format. When the investigation completes the results will be written to the reports directory. Claude chat logs will also be copied to the logs directory. You can double-click on `report.html` in reports to view an interactive HTML interface to the results and log data.
