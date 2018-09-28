<#
    SimpleJiraMonitor v1
    This script queries a specific JIRA project and sends an HTML report by email
#>

#################################  Define variables
# JIRA API settings
#- Avoid putting plaintext password at all cost! This is just to simplify it here.
#- For an ecnryption solution, please see my code snippets in https://github.com/lambdac0de/encrypt_credential
$JiraUser = "<jira_api_user>"
$JiraPassword = "<jira_api_password>"
$ProjectKey = "<jira_project_key>"
$maxRecords=-1 # Set to -1 to have no maximum records (gets all)
$JiraHost = 'myjiraserver.mydomain.com'
$Jira_closed_states = @('Resolved','Closed') # If you defined other Jira states that represent a closed/ resolved state, add them in this array

# This will be the Jira endpoint and query url from given input
# It uses the Search endpoint of the Jira API. A different version may already exist as you read this, so update it as needed
$JiraAPIUri = "https://$JiraHost/jira/rest/api/2/search?jql=project=$ProjectKey&maxResults=$maxRecords"

# Email settings
$emailfrom = 'Simple JIRA Monitor <noreply@simplyjiramonitor.com>' # Change sender address as needed
$emailto = @('<recipient_1>,<recipient_2>,<recipient_n>')
$smtp_server = '<smtp_server_hostname>'
$smtp_port = 25 # default SMTP port, or change as needed
$subject = 'Unresolved JIRA tickets' # Change subject as needed

# Report settings
$report_title = 'Pending Open Tickets' # This will be the title of the HTML report
$text_font = 'Tahoma' # Style it differently as needed
$table_font = 'Arial' # Style it differently as needed

# Other program variables
$LogPath = '<path_to_logfile>'
$timeOut = 500 # Timeout in seconds before the script fails when querying Jira
#################################

#################################  Define HELPER functions
function Log-Message {
    param([string]$message)

    try {
        $datedisplay = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Output "$datedisplay $message" >> $LogPath
    }
    catch {
        # Do nothing
    }
}

function Get-JiraTickets {
    <#
        Review your JIRA project's custom fields to add them in the report
        This script will only include some default Jira fields
    #>

    $ticketsObj = @()
    $password_header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$JiraUser`:$JiraPassword"))
    $Headers = @{'X-Atlassian-Token'="nocheck";
                 'Authorization'="Basic $password_header";
                }
    try {
        $post_result = Invoke-WebRequest -Uri $JiraAPIUri -Method Get -Headers $Headers -TimeoutSec $timeOut -UseBasicParsing
        $issues = ($post_result.Content | ConvertFrom-Json).issues.fields

        if ($issues.Count -gt 0) {
            foreach ($issue in $issues) {
                if ($issue.status.name -notin $Jira_open_states) {

                    $Jira = '<a href=https://' + $JiraHost + '/jira/browse/' + $issue.watches.self.Split('/')[8] + '>' + $issue.watches.self.Split('/')[8] + '</a>'
                    $emailaddress = $issue.assignee.emailAddress
                    if ($global:emailsCol -notcontains $emailaddress -and ![string]::IsNullOrWhiteSpace($emailaddress)) {
                        $global:emailsCol += $emailaddress
                    }

                    # If you want to add a custom field, add them in this hash table as:
                    # 'Custom Field Title'=$issue.customfield_<field_number>.value
                    $props = [ordered]@{'JIRA'=$Jira;
                                        'Status'= $issue.status.name;
                                        'Last Updated'=[datetime]$issue.updated;
                                        'Ticket Age' = ((Get-Date) - [datetime]$issue.created).Days
                                        'Reporter'=$issue.reporter.displayName
                                        'Assignee'=$issue.assignee.displayName         
                    }
                    if ([string]::IsNullOrWhiteSpace($props.Assignee)) {
                        $props.Assignee = "Not Assigned"
                    }
                    if ([string]::IsNullOrWhiteSpace($props.'Affected System')) {
                        $props.'Affected System' = "unspecified"
                    }
                    $ticketObj = New-Object -TypeName psobject -Property $props
                    $ticketsObj += $ticketObj
                }
            }
            return $ticketsObj
        }
        else {
            Log-Message ("[INFO]: No Open Jira ticket to process")
            return $false
        }
    }
    catch {
        Log-Message ("[ERROR]: " + $Error[0].Exception)
        return $false
    }
}

# This is what the HTML report will look like
# It will be sent as an inline message in the email
# If you know how to do markups in HTML, edit this as needed to suit your needs
function Format-Email {
    param (
        [psobject[]] $tickets
    )
    $current_date = (Get-Date).ToString("D")
    $body = ($tickets | ConvertTo-Html -Fragment).Replace('&lt;','<').Replace('&gt;','>').Replace('<table>',"<table cellpadding=`"5`" style=`"font-family: $table_font; font-size: 12px; border: 1px solid black; border-collapse: collapse;`">").Replace('border=0','border=1')
    $body = $body.Replace('Not Assigned','<i>Not Assigned</i>')
    $body = $body.Replace('Not Specified','<i>Not Specified</i>')
    $body = $body.Replace('unspecified','<i>unspecified</i>')

    $messageText = [string]::Empty
    $messageText += "<!DOCTYPE html>`n"
    $messageText += "<head>`n"
    $messageText += "     <title>$report_title</title>`n"
    $messageText += "     <style>td {vertical-align: top; text-align: left; border: 1px solid darkgrey; border-collapse: collapse;}`n"
    $messageText += "            table,td {border: 1px solid black; border-collapse: collapse;}`n"
    $messageText += "            th {color: white; background-color: black;}</style>`n"
    $messageText += "</head>`n"

    $messageText += "<body>`n"
    $messageText += ("   <p style='font-family: $text_font; font-size: 12px;'>Hi all,<br><br> Please see pending unresolved tickets from JIRA as of <b>$current_date</b>:<br>`n")
    $messageText += $body
    $messageText += ("   <p style='font-family: $text_font; font-size: 12px;'>Total count of Open tickets: <b>" + $tickets.Count + "</b>`n")
    $messageText += ("   <p style='font-family: $text_font; font-size: 12px;'><span style='color: red;'><i><b>Note:</b></i></span> If you are not expecting this email but have received it nonetheless, this is because you are currently an Assignee in one or more tickets. Kindly update the ticket(s) as needed. Thank you.<br>`n")
    $messageText += "</body>`n"

    return $messageText
}

function Send-Email
{
    [CmdletBinding()]
    param(

    [Parameter(Position=1)]
    [string[]]$To,
    [Parameter(Position=2)]
    [string[]]$CC,
    [Parameter(Position=3)]
    [string[]]$From,
    [Parameter()]
    [string]$SMTPServer,
    [Parameter()]
    [string]$SMTPPort = 25,
    [Parameter()]
    [string]$Subject,
    [Parameter()]
    [string]$Body,
    [Parameter()]
    [switch]$Error
    )
    BEGIN {}
    PROCESS {
        $SMTPmessage = New-Object Net.Mail.MailMessage($From,$To)
        if ($PSBoundParameters.ContainsKey('CC')) {
            foreach ($address in $CC) {
                $SMTPmessage.CC.Add($address)    
            }
        }
        $SMTPmessage.Subject = $Subject
        $SMTPmessage.IsBodyHtml = $true
        $SMTPmessage.Body = $Body
       
        if ($PSBoundParameters.ContainsKey('Error')) {
            $SMTPmessage.Priority = [System.Net.Mail.MailPriority]::High
            $SMTPmessage.Subject = ("[ERROR]" + $Subject)
        }
        $SMTPClient = New-Object Net.Mail.SmtpClient($SMTPServer,$SMTPPort)
        try{
            $SMTPClient.Send($SMTPmessage)
            return $true
        }
        catch [Exception] {
            Log-Message "[ERROR]: Unable to send email"
            return $_
        }
    }
    END {
        $SMTPmessage.Dispose()
    }
}
#################################

################################# MAIN program flow
$global:emailsCol = @()
$tickets = Get-JiraTickets | Sort-Object -Property 'Ticket Age' -Descending

# At some point, Jira started requiring explicit protocol definition during TLS handshake
[System.Net.ServicePointManager]::SecurityProtocol = @("Tls12","Tls11","Tls")
    
if ($tickets -eq $false) {
    exit 1
}
else {
    if ($tickets.Count -eq 0) {
        Log-Message "[WARNING]: No issues obtained. Nothing to do..."
        exit 1
    }
    else {
        $messageStr = Format-Email -tickets $tickets
        $emailProps = @{'To'=$emailto;
                        'CC'=($global:emailsCol | Get-Unique);
                        'From'=$emailfrom;
                        'SMTPServer'=$smtp_server;
                        'SMTPPort'=$smtp_port;
                        'Subject'=$subject;
                        'Body'=$messageStr;
                        }

        if (Send-Email @emailProps) {
            Log-Message "[SUCCESS] Open tickets in Jira successfully queried and emailed to recipients"
        }
        else {
            Log-Message ("[ERROR] Unable to send email" + $Error[0].Exception)
        }
    }
}
#################################
