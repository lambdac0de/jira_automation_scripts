# jira_automation_scripts
This repository contains standalone PowerShell scripts that provide automation for some of the more common tasks associated with the Jira bug tracking (ticketing) tool

### Simple Jira Monitor (SimpleJiraMonitor.ps1)
This is a script to query all open tickets in your Jira project and send a formatted HTML report containing these open tickets to your defined recipients as well as all 'assignees' of the open tickets.<br><br>
This script assumes that you have an <b>API credential</b> to access you Jira project, as well as a reacheable <b>SMTP smart host</b> that allows sending of emails without authentication.
#### Usage
1. Review the `JIRA API settings` section of the script and ensure that you have entered correct values for the following variables: `$JiraUser`,`$JiraPassword`,`$ProjectKey`,`$JiraHost`
2. Review the `Email settings` section of the script and ensure that you have entered correct values for the following variables: `$emailfrom`,`$emailto`,`$smtp_server`,`$subject`
3. Define path to generated log file in variable `$LogPath`
4. That's it, just run the script or schedule it in Task Scheduler
