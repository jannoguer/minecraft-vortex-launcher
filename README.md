## Vortex Minecraft Launcher

Fast, lightweight and easy to use Minecraft launcher. Natively available for Windows and Linux.

---

## Features

* Lightweight and fast
* Open-Source
* Cross-Platform (available for Windows and Linux)
* Supports all Minecraft versions
* Supports Forge and other APIs
* Downloads all Minecraft versions
* Downloads missing libraries
* Doesn't require Minecraft account
* Doesn't require Java to work
* Can work fully offline
* Optional Microsoft account login for the official online mode

---

## Microsoft account (official online mode)

The launcher works without an account by default. To play on online-mode
servers, enable "Use Microsoft account (official)" in Settings and log in
with a Microsoft account that owns Minecraft: Java Edition. The login uses
the device code flow: the launcher shows a short code and a microsoft.com
link where the code must be entered.

This feature requires an Azure application client ID that Mojang has
approved for the Minecraft services API. If the built-in ID is empty or
rejected, a custom one can be set with the `MsaClientId` key in
`vortex_launcher.conf`.

Note: the Microsoft refresh token is stored in plain text in
`vortex_launcher.conf`. Log out (Settings) before sharing that file or the
launcher directory.

---

## Download

Check the [**Releases**](https://github.com/Kron4ek/minecraft-vortex-launcher/releases) page to download the latest launcher version.

---

## Screenshots

![settings](https://i.imgur.com/dkiweug.png)
![main window](https://i.imgur.com/pd2tnnK.png)
![client downloader](https://i.imgur.com/1QTjiDw.png)

---

## License

[GPLv3](https://github.com/Kron4ek/minecraft-vortex-launcher/blob/master/LICENSE.txt)

---

### Mirrors

Mirror on GitLab: https://gitlab.com/Kron4ek/vortex-minecraft-launcher
