
# RSCS Mail

This was an attempt to funnel SMTP into RSCS for reading with PROFS on vintage systems that expanded

Currently it supports receiving mail for multiple domains to nodes defined in the config and available via RSCS

Only tested with nje-ii and PUBVM


## Features

- Redirect email to users
- Listens to a nje-ii user spool for sending mail
- DKIM Signing of mail
- Spam rejection


## Deployment
This project only uses the native Go build tools:

```bash
  go build
  ./rscsmail
```

Ensure your config.toml is set up for your domain before launching!
## License

[WTFPL](https://choosealicense.com/licenses/wtfpl/)


## Used By

This project is used by the following:

- PUBVM


## Support

No

