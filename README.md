# PKI.js Sign/Verify Example Outlook Add-in

This project is the sign/verify equivalent to https://github.com/gmu-msl/pkijs_outlook_addin_example. Both the sign/verify functionalities work as expected in both the Outlook add-in environment, as well as the separate unit tests.

## Installation

It should be noted that Microsoft does not currently support locally hosting a sideloaded add-in from Linux environments. Windows environments and Mac environments will work just fine, however.

This example will be "sideloaded" which means hosting the add-in locally and installing the add-in manifest into Outlook. This process is described by Microsoft in depth [here](https://docs.microsoft.com/en-us/office/dev/add-ins/outlook/sideload-outlook-add-ins-for-testing). Below are the basics of what you will need to do to achieve sideloading this add-in. It will be assumed you will be installing it via the browser for easy access to browser debugging/console tools.

- Download this add-in:
    - `git clone https://github.com/gmu-msl/pkijs_outlook_addin_example`

- Install add-in
    - Begin composing a new email
    - Click the three dots at the bottom right of the compose box
    - Click the **Get Add-ins** button
    - Click the **My add-ins** tab on the left
    - Click on the **+ Add a custom add-in** button
    - Choose **Add from file**
    - Choose the `manifest.xml` file found in the folder you downloaded in the previous step

- Begin hosting the actual add-in itself from the localhost
    - Navigate to the root of the project folder you downloaded in the previous step
    - Run `npm install` to install all the needed dependencies
    - Run `npm run dev-server`

## Demonstrating the working functionalities

The same certificate and key are used within the unit tests and the add-in itself (found in `src/tests/certAndKey.ts`).

To run the unit tests (`src/tests/encryptDecrypt.test.ts`), simply run `npm run testWindows` or `npm run testMac` for your appropriate platform.

The add-in functions via buttons available while composing an email. Simply type an email body, navigate to the same 3 dots from the installation process, and click `Sign current email` found under "PKI.js Example Add-in". This will replace the current email body with the encrypted S/MIME text of whatever you typed in.

To attempt to decrypt, follow the same process except click `Verify current email` instead. You should notice a success message pop up. You may modify the contents of the signed email and then click the button again to notice that it also properly fails to verify the email. The add-in tries verifies the body of the current email, making sure to strip it of its surrounding HTML tags and extract ONLY the S/MIME message section.

## Discussion

If you have any ideas about what could be causing the difference in behavior and/or any potential fixes, please feel free to open an issue or discussion for discussion.

Stack Overflow post discussing the encrypt/decrypt discrepencies: https://stackoverflow.com/questions/68060225/encryption-decryption-functions-working-differently-within-outlook-add-in-versus