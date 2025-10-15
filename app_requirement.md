# BHPetrol Email Testing Tool

This email testing tool provides a command line program to test email sending capability and status of all email servers under BHPetrol.

## Functional Requirement

- User can define:
  - the SMTP server to use
  - the from address
  - then receipient address/addresses
  - the login id and password
- The tool should support configurable plain and secure connection to the SMTP server
- The tool should be able to send the required email, track its communication with the SMTP service and report back the status of the email sending activity.
- The tool should allow user to define the subject and the content of the message to use as the test email.

## System Requirement

- develop using golang
- offer command line interface
- output to standard output as well as into file/logfile
