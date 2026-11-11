# Hotel Maninjau Indah PMS

The PMS must be opened through its Node.js server; opening `Index.html` directly does not authenticate users or save data to the shared database.

## Requirements

- Node.js 20 or newer
- npm

## First-time setup

1. Open a terminal in this folder.
2. Run `npm install`.
3. Run `npm run setup-accounts`.
4. Enter a display name and create a password for each account. Passwords are entered without being displayed and must be at least 12 characters.
5. Run `npm start`.
6. Open `http://127.0.0.1:3000`.

The setup creates these usernames:

- `owner` — Owner
- `manager` — Manager
- `it-support` — IT Support
- `staff` — Staf / Resepsionis (operational access only)

Enter and keep each password in a password manager. Passwords are stored as bcrypt hashes, not plain text. Re-running account setup leaves accounts that already exist unchanged and creates any missing account.

## Data and access

Authenticated Owner, Manager, IT Support, and Staf / Resepsionis accounts can open the PMS. The staff account cannot open or change the room price, benefit, and discount settings; the server also preserves those settings when staff save operational updates. Staff may still see the room rates and included benefits used by reservation and check-in workflows. Login sessions, accounts, room data, and room settings are stored in `data/hotel-maninjau.sqlite`. Stop the server before backing up this folder; keep it out of public web roots and source control.

On the first server start, the database starts with the configured 26-room inventory. Data previously stored by opening the standalone `file://` page is not automatically transferred into the server database.

The server binds to `127.0.0.1` by default. For access from other devices, deploy behind HTTPS with a correctly configured reverse proxy; set `NODE_ENV=production` and `TRUST_PROXY=1` only when HTTPS is terminated by that proxy. Do not expose the app directly to the internet.

The setup command provisions the four fixed accounts above and does not change existing accounts when run again. Do not create a frontend-only account or store passwords in HTML, JavaScript, or browser storage.
