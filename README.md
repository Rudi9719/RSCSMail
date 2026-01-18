
# RSCS Mail

This was an attempt to funnel SMTP into RSCS for reading with PROFS on vintage systems that expanded

Only tested with [nje-ii](https://github.com/HackerSmacker/nje-ii) RSCS and PUBVM. 
**Ensure NJE-II is working on your SMTP NODE and able to communicate with your RSCS node first!**
**Ensure your DNS records are set up for your domain before running this project!**


## Features

- Redirect internet email to CMS via RSCS
- Spam rejection using domain, sender, recipient, and modern DMARC/DKIM/SPF features
- Listens to a configureable nje-ii user spool for relaying RSCS notes to internet
- Only relay mail from the RSCS node **not** the internet
- Auto generation of DKIM key if domain is missing one
- Display of Domain to DKIM DNS Record mapping
- DKIM Signing of outbound mail
- Mail bounce notifications
- Support for IBM PROFS in 2025


## Deployment
This project only uses the native Go build tools, and allows an optional config.toml to be specified.

```bash
  go build
  ./rscsmail (/path/to/config.toml)
```

**Ensure your config.toml is set up for your domain before launching!**
**The NJE-ii run as user must exist locally on the SMTP node** 

## Sending a note to email
To send a note to email you must spool it to your configured nje-ii node and SMTP user.
For example PUBVM uses SMTP@PUBNET for RSCS Mail. I will show you how this invocation looks:

 - For CMS Notes

```bash
  NOTE SMTP AT PUBNET
```
 - PROFS is interface driven, so you just need to address PUBNET(SMTP) or your SMTP NODE(USER) 


 Once you're started, CMS and PROFS are different. While you're editing the note you will need the following:
 - **Only for PROFS,** you must put a blank line after headers or formatting will clobber the lines together.
 - From (Optional, will be generated however accepts an author per [RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322#appendix-A.1.2))
 - Subject (Optional, just type Subject: for CMS Notes on a new line)
 - To (Required, RSCS Mail will ignore the to user for SMTP, so you need a To: line with an internet address)
   - Multiline is supported, if you need more room simply begin a new line with To: and continue
   - Currently to use PROFS "reply" you must re-specify To: in the body like a new email
 - CC (Optional, just type CC: and your recipients - multiline is supported)
 - BCC (Optional, just type BCC: and your recipients - multiline is supported)
 - Body (Required, just type your message!)

## License

[WTFPL](https://choosealicense.com/licenses/wtfpl/)


## Used By

This project is used by the following:

- PUBVM


## Support

No


## Acknowledgements

 - [The PUBVM Team](https://www.pubvm.org)
 - [NJE-ii](https://github.com/HackerSmacker/nje-ii)
 - [RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322)
 - [BurntSishi/toml ](github.com/BurntSushi/toml)
 - [Emersion's Go Packages](https://github.com/emersion)
 - [Mileusna's SPF Go Package](https://github.com/mileusna/spf)
 - [MX Toolbox for Debugging](https://mxtoolbox.com)
 - [This guy's overview](https://stackoverflow.com/questions/9427013/send-email-using-telnet/79698345#79698345)
