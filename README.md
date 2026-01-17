
# RSCS Mail

This was an attempt to funnel SMTP into RSCS for reading with PROFS on vintage systems that expanded

Currently it supports receiving mail for multiple domains to nodes defined in the config and available via RSCS

Only tested with [nje-ii](https://github.com/HackerSmacker/nje-ii) RSCS and PUBVM. 
**Ensure NJE-II is working and able to communicate with your RSCS node before building this project!**
**Ensure your DNS records are set up for your domain before running this project!**

## Features

- Redirect internet email to RSCS nodes
- Spam rejection based on domain, sender, recipient, and modern DMARC/DKIM/SPF
- Listens to a configureable nje-ii user spool for relaying RSCS notes to internet
- Only relay mail from RSCS **not** the internet
- Auto generation of DKIM key if domain is missing one
- Display of Domain to DKIM DNS Record mapping
- DKIM Signing of outbound mail


## Deployment
This project only uses the native Go build tools:

```bash
  go build
  ./rscsmail
```

**Ensure your config.toml is set up for your domain before launching!**

## Sending a note to email
To send a note to email you must spool it to your configured nje-ii node and SMTP user.
For example PUBVM uses SMTP@PUBNET for RSCS Mail. I will show you how this invocation looks:

 - For CMS Notes

```bash
  NOTE SMTP AT PUBNET
```
 - For PROFS

 PROFS is interface driven, so you just need to address PUBNET(SMTP) or your SMTP NODE(USER) 


 Once you're started, CMS and PROFS are different. While you're editing the note you will need the following:
 - **Only for PROFS,** you must put a blank line after headers or formatting will clobber the lines together.
 - From (Optional, will be generated however accepts an author per [RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322#appendix-A.1.2))
 - Subject (Optional, just type Subject: for CMS Notes on a new line)
 - To (Required, RSCS Mail will ignore the to user for SMTP, so you need a To: line with an internet address)
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
