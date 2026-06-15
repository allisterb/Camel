# Camel

## About
The Camel project is a code-mode MCP server that allows LLMs to safely generate and execute JavaScript code that calls command-line forensic tools, performs analysis, and employs traditional machine learning algorithms and probabilistic reasoning using [SIFT workstation](https://www.sans.org/tools/sift-workstation), for autonomous DFIR investigations. 

## Demo video
[![](https://markdown-videos-api.jorgenkh.no/youtube/PkPXGt_iNX8)](https://youtu.be/PkPXGt_iNX8)

## Requirements
* A SIFT workstation instance either locally installed or remotely accessible over SSH
* .NET 9
* Claude Desktop or Claude Code

## Getting started
0. If you want to build from source: `git clone https://github.com/allisterb/Camel --recurse`.

1. Either download the latest Windows or Linux release to your computer or build Camel by running the build script from the repo folder.
2. Edit the appsettings.json file in your Camel runtime folder (`src/Camel.CLI/bin/Release/net9.0` if building or just the release archive folder) and set your SIFT environment preference: Local/Ssh. If using Ssh enter the login details for the SIFT workstation.

3. From the `Camel` folder run `[./]camel create-case <case_dir> <case_id>`
where <case_dir> is the path to your cases directory and <case_id> is your case id. Camel will create a case directory at the specified path with the CLAUDE.md prompt file and other supporting files and directories.

4. Edit <case_dir>/<case_id>/CLAUDE.md and fill in the Case description and Evidence sections with your case details and the filepaths to the evidence files on the SIFT workstation.

5. Start a new Claude session in <case_dir>/<case_id>.

6. Tell the agent to begin the investigation. The agent will first check if the required evidence files are present. If you provide hashes in the CLAUDE.md it will ask  you if you want to verify the evidence files first. After it confirms the evidence, the investigation will proceed autonomously.

7. As the investigation proceeds audit log data is written to the logs directory in CLEF format. When the investigation completes the results will be written to the reports directory. Claude chat logs will also be copied to the logs directory. You can double-click on `report.html` in reports to view an interactive HTML interface to the results and log data when the investigation completes.