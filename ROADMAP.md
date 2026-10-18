KEYFORGE: DEVELOPMENT ROADMAP

Project goal:

Build an offline password generator and password manager using Python and PySide6 for Windows.

PHASE 1: FOUNDATION (COMPLETED)

\- Create the Git repository

\- Set up a Python virtual environment

\- Install PySide6 and pytest

\- Create the project folder structure

\- Configure .gitignore

\- Write the README

\- Make the first Git commit

Goal: A clean project that runs and can be tested.

PHASE 2: PASSWORD GENERATOR ENGINE

\- Generate secure random passwords using Python's secrets module

\- Allow configurable password length

\- Support uppercase letters, lowercase letters, numbers, and symbols

\- Validate user settings

\- Handle invalid configurations and edge cases

\- Write unit tests

Goal: Generate secure passwords through the terminal without a GUI.

PHASE 3: DESKTOP USER INTERFACE

\- Build the main window using PySide6

\- Add a password length slider

\- Add character-set checkboxes

\- Add a Generate button

\- Add a Copy button

\- Add password visibility controls

\- Display errors clearly

\- Implement best-effort clipboard clearing

Goal: Generate and copy passwords through a desktop interface.

PHASE 4: PASSWORD ANALYZER

\- Estimate password entropy based on the generation method

\- Display password length and character diversity

\- Warn about short or predictable passwords

\- Explain why a password may be weak

\- Avoid presenting simplistic strength scores as security guarantees

\- Write unit tests

Goal: Help users understand password security.

PHASE 5: ENCRYPTED PASSWORD VAULT

\- Design a versioned vault file format

\- Create master-password authentication

\- Derive encryption keys using a suitable password-based key derivation function, such as Argon2id

\- Use a maintained cryptography library for authenticated encryption, such as AES-GCM

\- Implement adding, editing, viewing, and deleting credentials

\- Implement vault locking and unlocking

\- Handle incorrect master passwords

\- Detect corrupted or tampered vault files

\- Document backup and recovery limitations

Goal: Store account credentials in an encrypted local vault.

PHASE 6: SECURITY HARDENING

\- Review how sensitive information is handled in memory

\- Prevent passwords and credentials from appearing in logs

\- Test malformed inputs and damaged files

\- Add automatic vault locking after inactivity

\- Use privacy-focused defaults

\- Review dependencies and update them regularly

\- Test clipboard-clearing behavior and its limitations

Goal: Reduce the risk of accidental exposure and common security mistakes.

PHASE 7: TESTING AND RELEASE

\- Run the complete test suite

\- Test the application on a clean Windows environment

\- Package the application into a Windows executable

\- Verify that the application works offline

\- Document installation and usage

\- Document known limitations

\- Create a Git release tag

Goal: Produce a reproducible Windows build.

SUGGESTED PROJECT STRUCTURE

KeyForge/

&#x20;   main.py

&#x20;   requirements.txt

&#x20;   README.md

&#x20;   .gitignore

core/

&#x20;       generator.py

&#x20;       analyzer.py

security/

&#x20;       crypto.py

&#x20;       key\_derivation.py

storage/

&#x20;       vault\_store.py

ui/

&#x20;       main\_window.py

&#x20;       generator\_page.py

&#x20;       vault\_page.py

&#x20;       settings\_page.py

tests/

&#x20;       test\_generator.py

&#x20;       test\_analyzer.py

&#x20;       test\_vault.py

DEVELOPMENT RULES

\- Use Python's secrets module, never random, for password generation.

\- Never invent your own encryption algorithm.

\- Never store master passwords or vault credentials in plaintext.

\- Never commit secrets or real vault data to Git.

\- Keep the core logic independent of the user interface.

\- Test each feature before moving to the next phase.

\- Build the generator first. Do not implement the encrypted vault until the basic application works reliably.

