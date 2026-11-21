# iCloud Keychain for Linux

**Unofficial** client for iCloud Keychain. Sign in with your Apple ID and
`icp` registers this computer as one of your Apple devices, then downloads your passwords into a
private, encrypted store on your machine. A browser extension fills them in for you, just like the
Passwords app on a Mac or iPhone. Your Hide My Email addresses show up too. This project is a 
reverse engineering attempt and **is not affiliated with Apple in any way**.

> **Note:** Most of this project was written with AI assistance (and reviewed by a human).
> It works with my own Apple account, but that's no guarantee it will work with yours.
> Your passwords never leave your computer, and nothing is ever changed in your Apple
> account - `icp` only reads.

> This is also **untested** with Advanced Data Protection enabled. Any help with this will be appreciated -
> let me know if you have any issues with ADP enabled (also lmk if it works). Please don't spam escrow attempts!

## What you'll need

An **anisette server** running on your machine. Apple's sign-in needs a small piece of data that
only Apple's own software can produce; the anisette server provides it locally. Start one with
Docker (or Podman) - it keeps running in the background:

```
docker run -d --restart=always -p 6969:6969 dadoum/anisette-v3-server:latest
```

You only have to do this once. (If you run it somewhere other than the default
`http://localhost:6969`, set `ICP_ANISETTE_URL` to its address.)

You will also need this repo. Clone it / download it as you wish.

## Install

From the project folder:

```
python3 -m venv .venv && .venv/bin/pip install -e .
source .venv/bin/activate
```

## Sign in

```
icp login
```

This will walk you through the login: enter your Apple ID, password, and the 2FA code Apple
sends to your other devices. `icp` then asks for a **device passcode or iCloud Security Code** so
it can join your keychain.

- You're only asked for your password and 2FA code **once**. `icp` should stay signed in for a year after this.
- The passcode step is **important and can't be undone**: entering the wrong passcode too many
  times (about 10) will permanently lock your keychain recovery. One correct entry is
  perfectly safe.
- Your 2FA code and passcode are used immediately and **never saved**. Your password is
  **not saved by default** - when the long-lived tokens eventually expire (roughly every two
  months), re-run `icp login`. If you'd rather not re-login, pass `--save-password` to keep the
  password **encrypted on your computer** (in your login keyring) so `icp` can refresh tokens
  silently - it never leaves your machine either way. Your access tokens and passwords are
  stored encrypted the same way.

## Browse your passwords

```
icp show
```

Opens a full-screen list - start typing to filter, **Enter** to reveal a password,
**Ctrl+P** to copy the highlighted entry's password to the clipboard, **Ctrl+U** to copy
its username, **Ctrl+O** to copy
its current verification code and then quit (fetching a code is the last step of a
login workflow), **Esc** to quit. Wi-Fi (AirPort) passwords are excluded.
Entries with a custom name in the Passwords app show `Name (website)`. Add a word to
search directly, or `--plain` for plain text:

```
icp show github
```

The clipboard flags work in plain mode with a search term - `--copy-pw` copies the
password, `--copy-otp` the current verification code, `--copy-username` the username.
A term matching several logins prompts you to pick one (and aborts cleanly in
pipes/scripts). Copying falls back to the OSC 52 terminal escape sequence when no
clipboard tool exists (e.g. over SSH to a headless server):

```
icp show github --copy-pw
icp show microsoft --copy-otp
```

The `--get-*` flags print only the raw value on stdout (for scripts) - mutually
exclusive with each other, same match/disambiguation rules as the copy flags:

```
icp show github --get-pw
icp show github --get-otp
icp show github --get-username
```

## Verification codes

If a login has an authenticator code set up in the Passwords app, `icp` picks it up too. `icp show`
lists the current 6-digit code next to the login with the seconds left before it changes, counting
down live.

## Set up the browser extension

The `extension/` folder works in Chromium based browsers and Firefox.

### Chrome, Chromium, Helium, or Brave

1. Open your browser's extensions page (e.g. `chrome://extensions`, `helium://extensions`) and turn on **Developer
   mode**.
2. Click **Load unpacked** and choose the `extension/` folder. Copy the **Extension ID** it shows.
3. Connect the extension to `icp` by running:

   ```
   host/install.sh <EXTENSION_ID>
   ```

4. Reload the extension. Click its toolbar icon - you'll see the logins for the current site.

### Firefox

1. Open `about:debugging#/runtime/this-firefox`, click **Load Temporary Add-on...**, and choose
   `extension/manifest.json`. (Firefox removes temporary add-ons when it restarts, so you'll need
   to re-load it after restarting.)
2. Connect it to `icp`:

   ```
   host/install.sh
   ```

3. Click the toolbar icon to see logins for the current site.

If you ever move this project to a different folder, just run `host/install.sh` again.

## Filling in passwords

- On a sign-in page, click the username or password box - an **iCloud Passwords** dropdown appears
  with matching logins. Click one to fill it in (it handles email-first pages like Google too).
- Start typing to narrow the list.
- Or click the extension's toolbar icon and pick a login there.
- On a **two-factor code** box, the dropdown offers the current code instead - click to fill it.
  Pages that split the code across six separate boxes are filled a digit at a time. The code is
  always regenerated at the moment you click, so it is never a stale one, and the toolbar popup
  shows the code next to each login (click it to copy).

## Keeping your passwords up to date

Your passwords are a snapshot, so new or changed ones need a refresh. This happens
**automatically** in the background whenever the snapshot is more than 6 hours old - you don't have
to do anything. To refresh right now:

```
icp sync
```

## All commands

```
icp login    sign in, join your iCloud Keychain, and download your passwords
icp show     browse and search your passwords and Hide My Email addresses
icp sync     refresh your passwords now
icp logout   sign out (use --wipe-device to also forget this device)
```

`icp show` full-screen keys: type to filter, up/down move, **Enter** reveal,
**Ctrl+P** copy password, **Ctrl+U** copy username, **Ctrl+O** copy verification code and quit, **Esc** clear/quit.

`icp show <term>` flags:

```
-s, --show-passwords   reveal passwords in the plain listing
--copy-pw              copy password to clipboard
--copy-otp             copy current verification code to clipboard
--copy-username        copy username to clipboard
--get-pw               print only the password (for scripts)
--get-otp              print only the current verification code
--get-username         print only the username
```

Copy flags need a search term; several matches prompt you to pick one. Clipboard
copying falls back to the OSC 52 terminal escape when no clipboard tool is
available (e.g. over SSH to a headless server). See `icp -h` for the anisette
server setup and examples.

## Credits

The GrandSlam sign-in flow is adapted from [JJTech's reference](https://gist.github.com/JJTech0130/049716196f5f1751b8944d93e73d3452).
The keychain decryption, Octagon trust join, and CloudKit transport follow
[OpenBubbles/rustpush](https://github.com/OpenBubbles/rustpush), cross-checked against
[Apple's open-source Security code](https://github.com/apple-oss-distributions/Security). Hide My
Email is ported from [dedoussis's browser extension](https://github.com/dedoussis/icloud-hide-my-email-browser-extension).
Machine data is provided by the SideStore ecosystem's `anisette-v3-server`. See `RESEARCH.md` for
how it all works.
